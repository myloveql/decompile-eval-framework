from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from decomp_eval.config import validate_config
from decomp_eval.backends.command import CommandBackend
from decomp_eval.backends.ghidra import GhidraHeadlessBackend
from decomp_eval.backends.precomputed import PrecomputedBackend
from decomp_eval.backends.pseudocode import DatasetPseudocodeBackend
from decomp_eval.datasets.exebench import ExeBenchFlatAdapter
from decomp_eval.datasets.decompile_eval import DecompileEvalAdapter
from decomp_eval.models import (
    AssemblyInput, BinaryInput, CanonicalSample, EvaluationEvidence, PseudocodeInput,
)
from decomp_eval.metrics import BehavioralPassMetric, RecompilableMetric
from decomp_eval.plugins import plugin_inventory
from decomp_eval.postprocess import process_code
from decomp_eval.reporting import build_summary
from decomp_eval.runner import EvaluationRunner


PROJECT = Path(__file__).resolve().parents[1]
REPO = PROJECT.parents[1]


class FrameworkTests(unittest.TestCase):
    def _sample(self):
        return CanonicalSample(
            "d", "s", "id", "g", "target", "c", "O0",
            AssemblyInput("target:\n ret\n", "intel", "asm"), "hash",
        )

    def test_postprocess_is_explicit_and_audited(self):
        sample = CanonicalSample(
            "d", "s", "id", "g", "target", "c", "O0",
            AssemblyInput("ret", "intel", "asm"), "hash",
        )
        result = process_code("text\n```c\nint FUN_123(void){return 1;}\n```", sample, [
            "markdown_fence", {"type": "rename_target"}
        ])
        self.assertIn("target", result.code)
        self.assertEqual([a["processor"] for a in result.actions], ["markdown_fence", "rename_target"])

    def test_ghidra_compatibility_types_are_explicit_and_audited(self):
        result = process_code(
            "undefined4 target(undefined8 value) { return (undefined4)value; }",
            self._sample(), ["ghidra_compat_types"],
        )
        self.assertIn("typedef unsigned int undefined4;", result.code)
        self.assertIn("typedef unsigned long long undefined8;", result.code)
        self.assertEqual(result.actions[0]["processor"], "ghidra_compat_types")

    def test_summary_denominator_and_optimization(self):
        rows = []
        for opt, passed in (("O0", True), ("O1", False)):
            rows.append({
                "dataset_id": "d", "backend_id": "b", "split": "s", "language": "c",
                "optimization": opt, "decompile_success": True, "recompilable": passed,
                "behavioral_pass": passed, "reason": None if passed else "compile_error", "metrics": {},
            })
        summary = build_summary(rows)
        overall = summary["overall"][0]
        self.assertEqual(overall["total"], 2)
        self.assertEqual(overall["behavioral_pass_rate"], 0.5)
        self.assertEqual(len(summary["by_optimization"]), 2)

    def test_metrics_require_protocol_capabilities(self):
        evidence = EvaluationEvidence(protocol_id="syntax-only", capabilities=("candidate_compile",))
        self.assertIsNone(RecompilableMetric().evaluate(self._sample(), evidence))
        self.assertIsNone(BehavioralPassMetric().evaluate(self._sample(), evidence))
        supported = EvaluationEvidence(
            protocol_id="full",
            capabilities=("candidate_compile", "fixture_link", "behavioral_test"),
        )
        self.assertFalse(RecompilableMetric().evaluate(self._sample(), supported))
        self.assertFalse(BehavioralPassMetric().evaluate(self._sample(), supported))

    def test_reports_do_not_merge_different_protocols(self):
        rows = []
        for protocol in ("json-io", "exit-code"):
            rows.append({
                "dataset_id": "d", "backend_id": "b", "protocol_id": protocol,
                "protocol_version": "1", "split": "s", "language": "c",
                "optimization": "O0", "decompile_success": True, "recompilable": True,
                "behavioral_pass": True, "reason": None, "metrics": {},
            })
        summary = build_summary(rows)
        self.assertEqual(len(summary["overall"]), 2)
        self.assertEqual(
            {row["protocol_id"] for row in summary["overall"]}, {"json-io", "exit-code"}
        )

    def test_protocols_are_listed_as_plugins(self):
        inventory = plugin_inventory()
        self.assertIn("exebench_json_io", inventory["protocols"])
        self.assertIn("decompile_eval_exitcode", inventory["protocols"])
        self.assertIn("ghidra", inventory["backends"])

    def test_exebench_flat_loads_real_schema(self):
        row = {
            "sample_id": "eb:test:O0", "source_group_id": "eb:test",
            "function_name": "target", "optimization": "O0", "source_type": "fixture",
            "source_metadata": {"language": "c"}, "source": {"code": "int target(void){return 1;}", "signature": []},
            "assembly": {"objdump_att_instruction_only": "target:\n    mov $0x1, %eax\n    ret\n",
                         "objdump_att_instruction_only_syntax": "AT&T"},
            "decompilation": {"ghidra": {
                "code": "int target(void) { return 1; }", "producer": "ghidra",
                "version": "11.0.3", "sha256": "pseudo-hash",
            }},
            "evaluation": {},
        }
        with tempfile.TemporaryDirectory() as temp:
            dataset = Path(temp) / "exebench.json"
            dataset.write_text(json.dumps({"samples": [row]}), encoding="utf-8")
            adapter = ExeBenchFlatAdapter({
                "id": "eb", "path": str(dataset),
                "assembly_view": "objdump_att_instruction_only", "pseudocode_view": "ghidra",
            }, base_dir=PROJECT)
            samples = list(adapter.iter_samples())
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].assembly.syntax, "AT&T")
        self.assertEqual(samples[0].pseudocode.producer, "ghidra")
        self.assertIn("return 1", samples[0].pseudocode.text)
        self.assertNotIn("row", samples[0].public_request().to_dict())

    def test_decompile_eval_normalization_and_github_exclusion(self):
        row = {
            "index": 1, "func_name": "target", "func_dep": "", "func": "int target(void){return 1;}",
            "test": "int main(void){return target()==1?0:1;}", "opt": "O2", "language": "c",
            "asm": "target:\n ret", "ida_asm": "", "ghidra_asm": "",
            "ida_pseudo": "", "ghidra_pseudo": "int target(void){return 1;}",
        }
        fake = SimpleNamespace(load_from_disk=lambda path: [row])
        with patch.dict(sys.modules, {"datasets": fake}):
            adapter = DecompileEvalAdapter({
                "id": "de", "path": ".", "splits": ["humaneval"],
                "assembly_view": "asm", "pseudocode_view": "ghidra_pseudo",
            }, base_dir=PROJECT)
            sample = list(adapter.iter_samples())[0]
        self.assertEqual(sample.optimization, "O2")
        self.assertEqual(sample.assembly.syntax, "att")
        self.assertEqual(sample.pseudocode.view, "ghidra_pseudo")
        with self.assertRaises(ValueError):
            DecompileEvalAdapter({"id": "de", "path": ".", "splits": ["github"]}, base_dir=PROJECT)

    def test_config_rejects_duplicate_backend(self):
        with self.assertRaises(ValueError):
            validate_config({
                "datasets": [{"id": "d", "type": "x", "path": "p"}],
                "decompilers": [{"id": "b", "type": "x"}, {"id": "b", "type": "x"}],
                "preflight": {"mode": "off"},
            })

    def test_command_backend_protocol(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "artifacts"
            backend = CommandBackend({
                "id": "command-test",
                "command": [
                    sys.executable, str(PROJECT / "examples" / "toy_command_decompiler.py"),
                    "--assembly", "{assembly_file}", "--function", "{function_name}",
                    "--output", "{output_file}",
                ],
            })
            result = backend.decompile(self._sample().public_request(), output)
            self.assertTrue(result.success)
            self.assertIn("target", result.raw_output)
            request = json.loads((output / "request.json").read_text(encoding="utf-8"))
            self.assertNotIn("private_payload", request)

    def test_precomputed_backend_protocol(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "id.c").write_text("int target(void){return 1;}", encoding="utf-8")
            backend = PrecomputedBackend({"id": "pre", "path": str(root)}, base_dir=PROJECT)
            result = backend.decompile(self._sample().public_request(), root / "artifacts")
            self.assertTrue(result.success)
            self.assertIn("return 1", result.raw_output)

    def test_dataset_pseudocode_backend(self):
        sample = self._sample()
        sample.pseudocode = PseudocodeInput(
            "int target(void){return 1;}", "ghidra", "ghidra", "11.0.3", "hash"
        )
        backend = DatasetPseudocodeBackend({"id": "ghidra-fixed"})
        request = sample.public_request(backend.required_inputs)
        result = backend.decompile(request, Path("unused"))
        self.assertTrue(result.success)
        self.assertIn("return 1", result.code)
        self.assertEqual(request.assembly.text, "")
        self.assertIsNone(request.binary)

    def test_ghidra_backend_uses_binary_and_named_function(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ghidra = root / "ghidra"
            headless = ghidra / "support" / "analyzeHeadless"
            headless.parent.mkdir(parents=True)
            headless.write_text("fake", encoding="utf-8")
            binary = root / "sample.elf"
            binary.write_bytes(b"ELF fixture")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            sample = self._sample()
            sample.binary = BinaryInput(str(binary), digest, "ELF", "x86_64")
            backend = GhidraHeadlessBackend({
                "id": "ghidra-test", "ghidra_path": str(ghidra),
            }, base_dir=PROJECT)

            def fake_run(command, **kwargs):
                (Path(kwargs["cwd"]) / "backend_output.c").write_text(
                    "int target(void) { return 1; }", encoding="utf-8"
                )
                return SimpleNamespace(returncode=0, stdout="analysis complete", stderr="")

            with patch("decomp_eval.backends.ghidra.subprocess.run", side_effect=fake_run) as run:
                result = backend.decompile(sample.public_request(), root / "artifacts")
            self.assertTrue(result.success)
            command = run.call_args.args[0]
            self.assertIn("target", command)
            self.assertIn("DecompileFunction.java", command)
            self.assertTrue((root / "artifacts" / "input_binary.elf").exists())

    def test_backend_input_contract_distinguishes_binary_from_assembly(self):
        sample = self._sample()
        assembly_backend = SimpleNamespace(required_inputs=("assembly",))
        binary_backend = SimpleNamespace(required_inputs=("binary",))
        self.assertIsNone(EvaluationRunner._missing_backend_input(sample, assembly_backend))
        self.assertEqual(
            EvaluationRunner._missing_backend_input(sample, binary_backend), "binary_missing"
        )
        sample.binary = BinaryInput("fixture.elf")
        self.assertIsNone(EvaluationRunner._missing_backend_input(sample, binary_backend))
        self.assertEqual(sample.public_request(("binary",)).assembly.text, "")
        self.assertIsNone(sample.public_request(("assembly",)).binary)
        self.assertEqual(
            EvaluationRunner._missing_backend_input(
                sample, SimpleNamespace(required_inputs=("pseudocode",))
            ),
            "pseudocode_missing",
        )
        sample.pseudocode = PseudocodeInput("code", "ghidra", "ghidra")
        pseudocode_request = sample.public_request(("pseudocode",))
        self.assertEqual(pseudocode_request.pseudocode.text, "code")
        self.assertEqual(pseudocode_request.assembly.text, "")
        self.assertIsNone(pseudocode_request.binary)

    def test_end_to_end_python_plugin_and_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            config = {
                "_config_hash": "fixturehash",
                "_config_path": str(PROJECT / "fixture.yaml"),
                "workspace_root": str(PROJECT),
                "datasets": [{"id": "fixture", "type": "tests.fixtures:FixtureDataset", "path": "."}],
                "decompilers": [{
                    "id": "python-fixture", "type": "python", "plugin": "tests.fixtures:FixtureDecompiler",
                    "plugin_config": {"value": 7}, "batch_size": 4,
                }],
                "metrics": ["recompilable", "behavioral_pass"],
                "postprocessors": ["markdown_fence"],
                "executor": {"type": "local", "require_linux": False, "memory_mb": 512, "max_file_mb": 16},
                "preflight": {"mode": "strict"},
                "output": {"root": str(temp_path / "runs"), "cache": str(temp_path / "cache")},
            }
            run_dir = temp_path / "run"
            summary = EvaluationRunner(config, run_dir=run_dir).run()
            self.assertEqual(summary["overall"][0]["total"], 4)
            self.assertEqual(summary["overall"][0]["behavioral_pass_rate"], 1.0)
            self.assertEqual(summary["overall"][0]["protocol_id"], "fixture_exitcode")
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(
                manifest["evaluation_protocols"]["fixture"]["protocol_id"],
                "fixture_exitcode",
            )
            first_count = len((run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines())
            EvaluationRunner(config, run_dir=run_dir, resume=True).run()
            second_count = len((run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines())
            self.assertEqual(first_count, second_count)
            request = json.loads(next((run_dir / "artifacts").rglob("request.json")).read_text(encoding="utf-8"))
            self.assertNotIn("private_payload", request)
            cached_run = temp_path / "cached-run"
            EvaluationRunner(config, run_dir=cached_run).run()
            cached_rows = [json.loads(line) for line in (cached_run / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(all(row["cache_hit"] for row in cached_rows))
            self.assertEqual(len(list((cached_run / "artifacts").rglob("candidate.c"))), 4)
            changed = dict(config)
            changed["_config_hash"] = "different"
            with self.assertRaises(RuntimeError):
                EvaluationRunner(changed, run_dir=run_dir, resume=True).run()


if __name__ == "__main__":
    unittest.main()
