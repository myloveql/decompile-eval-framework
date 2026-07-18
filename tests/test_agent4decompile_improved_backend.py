from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from plugins.agent4decompile_improved_backend import (
    ImprovedAgent4DecompileBackend,
    ProtocolAlignedExeBenchL3,
)
from tests import test_agent4decompile_backend as base_tests


class _PromptRefiner(base_tests._FakeRefiner):
    def _build_prompt(self, code, constraints, iteration, binary_name, decompiler):
        return f"repair {binary_name}\n## Current Code\n```c\n{code}\n```"


class ImprovedAgent4DecompileBackendTests(unittest.TestCase):
    def setUp(self):
        base_tests._FakeCompletions.calls = []

    def test_improved_prompt_exposes_public_context_without_changing_base_backend(self):
        failed = subprocess.CompletedProcess(["gcc"], 1, "", "fixture error")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.agent4decompile_backend._import_agent4",
            return_value=(
                _PromptRefiner,
                base_tests._FakePipeline,
                base_tests._FakeConstraintEvaluator,
                base_tests._preprocess,
            ),
        ), patch.dict(
            sys.modules, {"openai": SimpleNamespace(OpenAI=base_tests._FakeOpenAI)}
        ), patch(
            "plugins.agent4decompile_backend.subprocess.run", return_value=failed
        ):
            root = Path(temporary)
            backend = ImprovedAgent4DecompileBackend(
                base_tests.Agent4DecompileBackendTests._backend_config(root)
            )
            artifact_dir = root / "artifacts"
            result = backend.decompile(
                base_tests.Agent4DecompileBackendTests._request(), artifact_dir
            )
            prompt = (artifact_dir / "iteration_00_prompt.txt").read_text(
                encoding="utf-8"
            )
            metadata = json.loads(
                (artifact_dir / "agent4_metadata.json").read_text(encoding="utf-8")
            )

        self.assertTrue(result.success)
        self.assertIn("## Public Compile Context", prompt)
        self.assertIn("#include <stdint.h>", prompt)
        self.assertLess(
            prompt.index("## Public Compile Context"), prompt.index("## Current Code")
        )
        self.assertEqual(metadata["implementation_variant"], "improved")
        self.assertEqual(
            metadata["candidate_selection"], "fine_grained_constraint_rank"
        )

    def test_protocol_aligned_l3_uses_formal_candidate_and_wrapper_semantics(self):
        request = base_tests.Agent4DecompileBackendTests._request()
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            evaluator = ProtocolAlignedExeBenchL3(
                request, Path(temporary), timeout=10
            )

            def fake_run(command, cwd):
                commands.append(command)
                if command[0].endswith("candidate.x"):
                    Path(command[2]).write_text(
                        json.dumps({"return": 7}), encoding="utf-8"
                    )
                return subprocess.CompletedProcess(command, 0, "", "")

            evaluator._run = fake_run
            passed, _, details = evaluator.evaluate_execution_exebench(
                "static int target(void) { return 7; }",
                [{"input": {}, "output": {"return": 7}}],
                'extern "C" {\nint target(void);\n}\nint main() { return 0; }',
                "typedef int fixture_type;",
                "int target(void)",
                "/fixture/exebench",
            )
            source = next(Path(temporary).glob("aligned_*/candidate.c")).read_text(
                encoding="utf-8"
            )
            wrapper = next(Path(temporary).glob("aligned_*/wrapper.cpp")).read_text(
                encoding="utf-8"
            )

        self.assertTrue(passed)
        self.assertEqual(details["passed"], 1)
        self.assertIn("#include <stdint.h>", source)
        self.assertNotIn("static int target", source)
        self.assertIn('#include "', wrapper)
        self.assertIn("-O2", commands[0])
        self.assertIn("-std=gnu11", commands[0])
        self.assertIn("-lm", commands[1])

    def test_repeated_identical_candidates_stop_early(self):
        failed = subprocess.CompletedProcess(["gcc"], 1, "", "fixture error")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.agent4decompile_backend._import_agent4",
            return_value=(
                _PromptRefiner,
                base_tests._FakePipeline,
                base_tests._FakeConstraintEvaluator,
                base_tests._preprocess,
            ),
        ), patch.dict(
            sys.modules, {"openai": SimpleNamespace(OpenAI=base_tests._FakeOpenAI)}
        ), patch(
            "plugins.agent4decompile_backend.subprocess.run", return_value=failed
        ):
            root = Path(temporary)
            config = base_tests.Agent4DecompileBackendTests._backend_config(
                root, max_iterations=5, stagnation_limit=2
            )
            artifact_dir = root / "artifacts"
            ImprovedAgent4DecompileBackend(config).decompile(
                base_tests.Agent4DecompileBackendTests._request(), artifact_dir
            )
            metadata = json.loads(
                (artifact_dir / "agent4_metadata.json").read_text(encoding="utf-8")
            )

        self.assertEqual(metadata["llm_calls"], 3)
        self.assertEqual(
            metadata["internal_error"], "Stopped after repeated identical candidates"
        )

    def test_fine_grained_rank_prefers_more_passing_l3_cases(self):
        def constraints(passed, failed):
            return {
                "syntax": {"pass": True},
                "compilation": {"pass": True},
                "execution": {
                    "pass": False,
                    "details": {"passed": passed, "failed": failed},
                },
            }

        self.assertGreater(
            ImprovedAgent4DecompileBackend._rank(constraints(4, 1)),
            ImprovedAgent4DecompileBackend._rank(constraints(1, 4)),
        )


if __name__ == "__main__":
    unittest.main()
