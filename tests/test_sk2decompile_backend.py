from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from decomp_eval.models import AssemblyInput, DecompileRequest, PseudocodeInput
from plugins.sk2decompile_backend import (
    SK2DecompileBackend,
    normalize_pseudocode_text,
    rename_generated_target,
)


class _FakeSK2Backend(SK2DecompileBackend):
    def __init__(self, **overrides):
        self.activations = []
        self.generated_prompts = []
        super().__init__({
            "struct_model_path": "LLM4Binary/sk2decompile-struct-6.7b",
            "ident_model_path": "LLM4Binary/sk2decompile-ident-6.7b",
            "engine": "vllm",
            "preprocess": False,
            "stage_batch_size": 2,
            **overrides,
        })

    def _activate_model(self, model_reference: str, stage: str) -> None:
        self.activations.append(("load", stage, model_reference))
        self._active_stage = stage
        self._active_model = object()
        self._active_tokenizer = object()

    def _deactivate_model(self) -> None:
        if self._active_stage:
            self.activations.append(("unload", self._active_stage, None))
        self._active_stage = None
        self._active_model = None
        self._active_tokenizer = None

    def _generate_active(self, prompts: list[str]) -> list[str]:
        self.generated_prompts.extend((self._active_stage, prompt) for prompt in prompts)
        if self._active_stage == "struct":
            return [f"int func1(void) {{ return {index + 1}; }}" for index, _ in enumerate(prompts)]
        return [
            f"int recovered_{index}(void) {{ return {index + 1}; }}"
            for index, _ in enumerate(prompts)
        ]


class SK2DecompileBackendTests(unittest.TestCase):
    @staticmethod
    def _request(index: int, *, language: str = "c", pseudocode: str | None = None):
        pseudo = pseudocode if pseudocode is not None else f"int sub_{index}(void) {{ return {index}; }}"
        return DecompileRequest(
            dataset_id="fixture",
            split="test",
            sample_id=f"sample-{index}",
            source_group_id=f"group-{index}",
            function_name=f"target_{index}",
            language=language,
            optimization="O2",
            assembly=AssemblyInput("", "att", "asm"),
            pseudocode=PseudocodeInput(pseudo, "ida_pseudo", "ida"),
            metadata={},
        )

    def test_official_text_normalization(self):
        normalized = normalize_pseudocode_text(
            "/* header */ _DWORD *__fastcall sub_10(_BYTE *a1) { // comment\n"
            "  return (_DWORD *)(0x20u + (__int64)a1);\n}"
        )
        self.assertNotIn("comment", normalized)
        self.assertNotIn("__fastcall", normalized)
        self.assertIn("uint32_t", normalized)
        self.assertIn("uint8_t", normalized)
        self.assertIn("32u", normalized)
        self.assertIn("long long", normalized)

    def test_target_rename_handles_pointer_return_and_recursive_calls(self):
        code = "char **recovered(char **x) { return recovered(x); }"
        renamed, old_name, count = rename_generated_target(code, "target")
        self.assertEqual(old_name, "recovered")
        self.assertEqual(count, 2)
        self.assertEqual(renamed, "char **target(char **x) { return target(x); }")

    def test_backend_runs_clang_format_after_text_normalization(self):
        backend = _FakeSK2Backend(preprocess=True)
        completed = SimpleNamespace(
            returncode=0,
            stdout="uint32_t *sub_10(void) {\n  return 32u;\n}\n",
            stderr="",
        )
        with patch(
            "plugins.sk2decompile_backend.subprocess.run",
            return_value=completed,
        ) as run:
            normalized = backend._format_pseudocode(
                "_DWORD *__fastcall sub_10(void) { return 0x20u; }"
            )
        self.assertEqual(normalized, "uint32_t *sub_10(void) {\n  return 32u;\n}")
        self.assertEqual(run.call_args.args[0], ["clang-format", "--style=Google"])
        self.assertIn("uint32_t", run.call_args.kwargs["input"])
        self.assertNotIn("__fastcall", run.call_args.kwargs["input"])

    def test_two_stage_pipeline_preserves_order_and_writes_audit_artifacts(self):
        backend = _FakeSK2Backend()
        requests = [self._request(0), self._request(1)]
        with tempfile.TemporaryDirectory() as temp:
            artifact_dirs = [Path(temp) / "a", Path(temp) / "b"]
            backend.prepare(requests)
            results = backend.decompile_many(requests, artifact_dirs)
            first_metadata = json.loads(
                (artifact_dirs[0] / "sk2_metadata.json").read_text(encoding="utf-8")
            )
            first_struct = (artifact_dirs[0] / "sk2_struct_output.c").read_text(
                encoding="utf-8"
            )
            first_ident_prompt = (artifact_dirs[0] / "sk2_ident_prompt.txt").read_text(
                encoding="utf-8"
            )

        self.assertEqual(
            [result.code for result in results],
            [
                "int target_0(void) { return 1; }",
                "int target_1(void) { return 2; }",
            ],
        )
        self.assertTrue(all(result.success for result in results))
        self.assertEqual(
            [entry[:2] for entry in backend.activations],
            [("load", "struct"), ("unload", "struct"), ("load", "ident")],
        )
        self.assertEqual(first_struct, "int func1(void) { return 1; }")
        self.assertIn("# This is the normalized code:", first_ident_prompt)
        self.assertEqual(first_metadata["generated_function_name"], "recovered_0")
        struct_prompts = [prompt for stage, prompt in backend.generated_prompts if stage == "struct"]
        self.assertTrue(all(prompt.startswith("# This is the assembly code:\n") for prompt in struct_prompts))

    def test_unsupported_language_becomes_per_sample_failure(self):
        backend = _FakeSK2Backend()
        request = self._request(0, language="cpp")
        with tempfile.TemporaryDirectory() as temp:
            backend.prepare([request])
            result = backend.decompile(request, Path(temp))
            metadata = json.loads(
                (Path(temp) / "sk2_metadata.json").read_text(encoding="utf-8")
            )
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "sk2_preprocess_failed")
        self.assertIn("unsupported", result.log)
        self.assertEqual(metadata["reason"], "sk2_preprocess_failed")
        self.assertEqual(backend.activations, [])

    def test_official_filter_is_optional_but_auditable(self):
        request = self._request(0, pseudocode="int f(void) { return 1; }")
        backend = _FakeSK2Backend(enforce_official_filter=True)
        with tempfile.TemporaryDirectory() as temp:
            backend.prepare([request])
            result = backend.decompile(request, Path(temp))
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "sk2_preprocess_failed")
        self.assertIn("official line filter", result.log)

    def test_missing_absolute_model_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            SK2DecompileBackend({
                "struct_model_path": "/definitely/missing/struct",
                "ident_model_path": "LLM4Binary/sk2decompile-ident-6.7b",
            })


if __name__ == "__main__":
    unittest.main()
