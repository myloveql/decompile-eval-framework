from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from decomp_eval.models import AssemblyInput, DecompileRequest, OracleContext, PseudocodeInput
from plugins.fidelitygpt_backend import FidelityGPTBackend


PROMPTS = '''from langchain.prompts import PromptTemplate
from langchain.schema import SystemMessage, HumanMessage, AIMessage

def create_RAG_prompt_template():
    return PromptTemplate.from_template("DETECT\\nCONTEXT={context}\\nQUESTION\\n{question}")

def create_RAG_promptwithvariable_template():
    return PromptTemplate.from_template(
        "DETECT\\nVARIABLES={Variable_names}\\nCONTEXT={context}\\nQUESTION\\n{question}"
    )

def create_RAG_correction_template():
    return PromptTemplate.from_template("CORRECT\\nCONTEXT={context}\\nQUESTION\\n{question}")
'''

PATTERN = '''def match_patterns(lines, fidelity_file_path="fidelity_new.c"):
    return [line for line in lines[1:] if line.strip()][:1]
'''

VARIABLES = '''def generate_cfg(c_code): return None, c_code.splitlines()
def compute_post_dominators(cfg): return {}
def generate_control_dependence_subgraph(cfg, post): return None
def generate_data_dependence_subgraph(lines): return None
def extract_variables(expression): return []
def extract_variable_definitions(c_code): return []
def generate_pdg(c_code): return None, c_code.splitlines()
def find_variable_dependencies(pdg, variable_name, lines): return []
def create_variable_template(): return PromptTemplate.from_template("VARIABLE {question}")
def format_prompt(all_dependencies): return "VARIABLE " + "\\n".join(all_dependencies)
'''


class _FakeEndpoint:
    def __init__(self, model: str, *, role: str):
        self.model = model
        self.role = role
        self.base_url = f"https://{role}.example/v1"
        self.temperature = 0.5
        self.prompts: list[str] = []
        self.closed = False

    def prepare(self):
        return None

    def embed(self, texts):
        vectors = []
        for text in texts:
            vectors.append([10.0] if "DOC_B" in text else [0.0])
        return vectors, {"texts": len(texts), "role": self.role}

    def chat(self, prompt):
        self.prompts.append(prompt)
        if prompt.startswith("VARIABLE"):
            return "Potential redundant variables: v1", {"stage": "variable"}
        question = prompt.split("QUESTION\n", 1)[1]
        if prompt.startswith("DETECT"):
            lines = question.splitlines()
            if lines:
                lines[-1] += " // I4"
            return "\n".join(lines), {"stage": "detection"}
        return "```c\nint target(void) { return 7; } //fixed\n```", {"stage": "correction"}

    def close(self):
        self.closed = True


class FidelityGPTBackendTests(unittest.TestCase):
    @staticmethod
    def _root(path: Path) -> Path:
        root = path / "FidelityGPT"
        root.mkdir()
        files = {
            "FidelityGPT.py": "# fixture\n",
            "Correction.py": "# fixture\n",
            "prompt_templates.py": PROMPTS,
            "pattern_matcher.py": PATTERN,
            "variabledependency.py": VARIABLES,
            "embedding_retriever.py": "# fixture\n",
            "document_processor.py": "# fixture\n",
            "fidelity_new.c": "DOC_A IDA\nDOC_B IDA\n",
            "fidelity_ghidra.c": "DOC_A GHIDRA\nDOC_B GHIDRA\n",
        }
        for name, content in files.items():
            (root / name).write_text(content, encoding="utf-8")
        return root

    @staticmethod
    def _request(code: str) -> DecompileRequest:
        return DecompileRequest(
            dataset_id="fixture",
            split="test",
            sample_id="fixture:0:O0",
            source_group_id="fixture:0",
            function_name="target",
            language="c",
            optimization="O0",
            assembly=AssemblyInput("", "att", "asm"),
            pseudocode=PseudocodeInput(code, "ghidra", "ghidra"),
            metadata={},
        )

    @staticmethod
    def _config(root: Path, **overrides):
        config = {
            "fidelitygpt_root": str(root),
            "chat": {
                "model": "vendor-chat",
                "base_url": "https://chat.vendor/v1",
                "api_key": "fixture",
            },
            "embedding": {
                "model": "vendor-embedding",
                "base_url": "https://embedding.vendor/v1",
                "api_key": "fixture",
            },
        }
        config.update(overrides)
        return config

    @staticmethod
    def _fake_endpoints(backend: FidelityGPTBackend):
        backend.chat_endpoint = _FakeEndpoint("vendor-chat", role="chat")
        backend.embedding_endpoint = _FakeEndpoint("vendor-embedding", role="embedding")
        backend.variable_endpoint = _FakeEndpoint("vendor-variable", role="variable")

    def test_short_function_runs_detection_rag_and_correction(self):
        code = "int target(void)\n{\nreturn 7;\n}"
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            backend = FidelityGPTBackend(self._config(root))
            self._fake_endpoints(backend)
            artifact_dir = Path(temporary) / "artifacts"
            result = backend.decompile(self._request(code), artifact_dir)
            metadata = json.loads(
                (artifact_dir / "fidelitygpt_metadata.json").read_text(encoding="utf-8")
            )
            detection_prompt = (artifact_dir / "detection_00_prompt.txt").read_text(
                encoding="utf-8"
            )

        self.assertTrue(result.success)
        self.assertEqual(result.code, "int target(void) { return 7; } //fixed")
        self.assertIn("DOC_A GHIDRA", detection_prompt)
        self.assertEqual(metadata["knowledge_base_documents"], 2)
        self.assertFalse(metadata["long_function"])
        self.assertEqual(metadata["chunk_count"], 1)
        self.assertFalse(metadata["oracle_assisted"])

    def test_long_function_uses_variable_context_and_merges_overlap(self):
        lines = [f"line_{index};" for index in range(8)]
        code = "\n".join(lines)
        variable_module = SimpleNamespace(
            generate_pdg=lambda value: (None, value.splitlines()),
            extract_variable_definitions=lambda value: ["v1"],
            find_variable_dependencies=lambda pdg, variable, source: ["v1 = line_1;"],
            format_prompt=lambda dependencies: "VARIABLE " + "\n".join(dependencies),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            backend = FidelityGPTBackend(
                self._config(root, block_size=5, overlap=2, overlap_conflict_policy="union")
            )
            self._fake_endpoints(backend)
            backend._variable_module = variable_module
            artifact_dir = Path(temporary) / "artifacts"
            result = backend.decompile(self._request(code), artifact_dir)
            metadata = json.loads(
                (artifact_dir / "fidelitygpt_metadata.json").read_text(encoding="utf-8")
            )
            merged = (artifact_dir / "fidelitygpt_detection_merged.c").read_text(
                encoding="utf-8"
            )
            second_prompt = (artifact_dir / "detection_01_prompt.txt").read_text(
                encoding="utf-8"
            )

        self.assertTrue(result.success)
        self.assertTrue(metadata["long_function"])
        self.assertEqual(metadata["chunk_count"], 2)
        self.assertEqual(metadata["chunk_merge_policy"], "source_line_aligned_overlap_merge")
        self.assertIn("Potential redundant variables: v1", second_prompt)
        self.assertEqual(len(merged.rstrip().splitlines()), len(lines))
        self.assertEqual(merged.count("line_3;"), 1)

    def test_overlap_label_conflict_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            backend = FidelityGPTBackend(
                self._config(root, block_size=3, overlap=1, overlap_conflict_policy="fail")
            )
            chunks = [(0, 3, ["a;", "b;", "c;"]), (2, 5, ["c;", "d;", "e;"])]
            with self.assertRaisesRegex(ValueError, "overlap label conflict"):
                backend._merge_detections(
                    ["a;", "b;", "c;", "d;", "e;"],
                    chunks,
                    ["a;\nb;\nc; // I1", "c; // I2\nd;\ne;"],
                )

    def test_upstream_variable_dependency_error_fails_open_and_is_audited(self):
        code = "\n".join(f"line_{index};" for index in range(6))
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            backend = FidelityGPTBackend(self._config(root, block_size=4, overlap=1))
            self._fake_endpoints(backend)
            backend._variable_module = SimpleNamespace(
                generate_pdg=lambda value: (_ for _ in ()).throw(KeyError("fixture-pdg"))
            )
            artifact_dir = Path(temporary) / "artifacts"
            result = backend.decompile(self._request(code), artifact_dir)
            metadata = json.loads(
                (artifact_dir / "fidelitygpt_metadata.json").read_text(encoding="utf-8")
            )
            variable_error_exists = (artifact_dir / "variable_error.txt").is_file()

        self.assertTrue(result.success)
        self.assertTrue(metadata["variable_llm"]["failed_open"])
        self.assertEqual(metadata["variable_llm"]["error_type"], "KeyError")
        self.assertTrue(variable_error_exists)

    def test_chat_embedding_and_variable_endpoints_are_independent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            config = self._config(root)
            config["variable_llm"] = {
                "model": "third-vendor-model",
                "base_url": "https://third.vendor/v1",
                "api_key": "fixture",
            }
            backend = FidelityGPTBackend(config)

        self.assertEqual(backend.chat_endpoint.base_url, "https://chat.vendor/v1")
        self.assertEqual(backend.embedding_endpoint.base_url, "https://embedding.vendor/v1")
        self.assertEqual(backend.variable_endpoint.base_url, "https://third.vendor/v1")
        self.assertEqual(backend.variable_endpoint.model, "third-vendor-model")
        self.assertEqual(backend.variable_endpoint.temperature, 0.5)

    def test_oracle_context_is_rejected_if_backend_is_misconfigured(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            backend = FidelityGPTBackend(self._config(root))
            request = replace(
                self._request("int target(void) { return 1; }"),
                oracle_context=OracleContext(protocol="fixture", payload={"secret": 1}),
            )
            result = backend.decompile(request, Path(temporary) / "artifacts")

        self.assertFalse(result.success)
        self.assertEqual(result.reason, "fidelitygpt_unexpected_oracle_context")


if __name__ == "__main__":
    unittest.main()
