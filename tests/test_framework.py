from __future__ import annotations

import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from decomp_eval.config import validate_config
from decomp_eval.backends.command import CommandBackend
from decomp_eval.backends.precomputed import PrecomputedBackend
from decomp_eval.datasets.exebench import ExeBenchFlatAdapter
from decomp_eval.datasets.decompile_eval import DecompileEvalAdapter
from decomp_eval.models import AssemblyInput, CanonicalSample, EvaluationEvidence
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

    def test_exebench_flat_loads_real_schema(self):
        row = {
            "sample_id": "eb:test:O0", "source_group_id": "eb:test",
            "function_name": "target", "optimization": "O0", "source_type": "fixture",
            "source_metadata": {"language": "c"}, "source": {"code": "int target(void){return 1;}", "signature": []},
            "assembly": {"objdump_att_instruction_only": "target:\n    mov $0x1, %eax\n    ret\n",
                         "objdump_att_instruction_only_syntax": "AT&T"},
            "evaluation": {},
        }
        with tempfile.TemporaryDirectory() as temp:
            dataset = Path(temp) / "exebench.json"
            dataset.write_text(json.dumps({"samples": [row]}), encoding="utf-8")
            adapter = ExeBenchFlatAdapter({
                "id": "eb", "path": str(dataset), "assembly_view": "objdump_att_instruction_only"
            }, base_dir=PROJECT)
            samples = list(adapter.iter_samples())
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].assembly.syntax, "AT&T")
        self.assertNotIn("row", samples[0].public_request().to_dict())

    def test_decompile_eval_normalization_and_github_exclusion(self):
        row = {
            "index": 1, "func_name": "target", "func_dep": "", "func": "int target(void){return 1;}",
            "test": "int main(void){return target()==1?0:1;}", "opt": "O2", "language": "c",
            "asm": "target:\n ret", "ida_asm": "", "ghidra_asm": "",
        }
        fake = SimpleNamespace(load_from_disk=lambda path: [row])
        with patch.dict(sys.modules, {"datasets": fake}):
            adapter = DecompileEvalAdapter({
                "id": "de", "path": ".", "splits": ["humaneval"], "assembly_view": "asm"
            }, base_dir=PROJECT)
            sample = list(adapter.iter_samples())[0]
        self.assertEqual(sample.optimization, "O2")
        self.assertEqual(sample.assembly.syntax, "att")
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

    def test_end_to_end_python_plugin_and_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            config = {
                "_config_hash": "fixturehash",
                "_config_path": str(PROJECT / "fixture.yaml"),
                "workspace_root": str(PROJECT),
                "datasets": [{"id": "fixture", "type": "fixtures:FixtureDataset", "path": "."}],
                "decompilers": [{
                    "id": "python-fixture", "type": "python", "plugin": "fixtures:FixtureDecompiler",
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
