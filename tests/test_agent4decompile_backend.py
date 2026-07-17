from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from decomp_eval.models import (
    AssemblyInput,
    CandidateCompileContext,
    DecompileRequest,
    PseudocodeInput,
)
from plugins.agent4decompile_backend import (
    Agent4DecompileBackend,
    FrameworkConstraintEvaluator,
)


class _FakeCompletions:
    calls: list[dict] = []

    def create(self, **kwargs):
        self.__class__.calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="int target(void) { return 7; }"))]
        )


class _FakeOpenAI:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.chat = SimpleNamespace(completions=_FakeCompletions())
        self.closed = False

    def close(self):
        self.closed = True


class _FakeRefiner:
    SYSTEM_PROMPT = "ORIGINAL AGENT4 SYSTEM PROMPT"

    def _build_prompt(self, code, constraints, iteration, binary_name, decompiler):
        return (
            f"ORIGINAL TEMPLATE|{iteration}|{binary_name}|{decompiler}|"
            f"{constraints['syntax']['pass']}|{code}"
        )

    @staticmethod
    def _extract_code(response):
        return response.strip()

    def refine(
        self,
        initial_code,
        binary_name,
        decompiler,
        original_binary_path=None,
        test_cases=None,
        exebench_data=None,
    ):
        constraints = self.evaluator.evaluate_all(
            initial_code,
            original_binary=original_binary_path,
            test_cases=test_cases,
            constraint_level=self.constraint_level,
            exebench_data=exebench_data,
        )
        prompt = self._build_prompt(initial_code, constraints, 0, binary_name, decompiler)
        candidate = self._extract_code(self._call_llm(prompt))
        return SimpleNamespace(
            success=False,
            refined_code=candidate,
            iterations=1,
            syntax_valid=False,
            compiles=False,
            re_executable=False,
            error_message="Max iterations reached",
            iteration_history=[{"iteration": 0}],
        )


class _FakePipeline:
    pass


def _preprocess(code: str, decompiler: str) -> str:
    return f"/* {decompiler} */\n{code}"


class Agent4DecompileBackendTests(unittest.TestCase):
    def setUp(self):
        _FakeCompletions.calls = []

    @staticmethod
    def _request() -> DecompileRequest:
        return DecompileRequest(
            dataset_id="fixture",
            split="test",
            sample_id="fixture:0:O2",
            source_group_id="fixture:0",
            function_name="target",
            language="c",
            optimization="O2",
            assembly=AssemblyInput("", "att", "asm"),
            pseudocode=PseudocodeInput(
                "int target(void) { broken }", "ghidra_pseudo", "ghidra"
            ),
            compile_context=CandidateCompileContext(
                language="c",
                compiler="gcc",
                flags=("-std=gnu11", "-w"),
                libraries=("-lm",),
                prelude="#include <stdint.h>",
            ),
            metadata={},
        )

    @staticmethod
    def _backend_config(root: Path, **overrides):
        config = {
            "agent4_root": str(root),
            "mode": "pseudocode_refine",
            "constraint_level": 2,
            "max_iterations": 1,
            "llm": {
                "provider": "openai_compatible",
                "base_url": "http://localhost/v1",
                "api_key": "test-only",
                "model": "fixture-model",
                "max_retries": 1,
            },
        }
        config.update(overrides)
        return config

    def test_original_prompt_methods_are_authoritative(self):
        failed = subprocess.CompletedProcess(["gcc"], 1, "", "fixture syntax error")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.agent4decompile_backend._import_agent4",
            return_value=(_FakeRefiner, _FakePipeline, _preprocess),
        ), patch.dict(sys.modules, {"openai": SimpleNamespace(OpenAI=_FakeOpenAI)}), patch(
            "plugins.agent4decompile_backend.subprocess.run", return_value=failed
        ):
            root = Path(temporary)
            backend = Agent4DecompileBackend(self._backend_config(root))
            artifact_dir = root / "artifacts"
            result = backend.decompile(self._request(), artifact_dir)
            metadata = json.loads(
                (artifact_dir / "agent4_metadata.json").read_text(encoding="utf-8")
            )
            saved_system_prompt = (artifact_dir / "agent4_system_prompt.txt").read_text(
                encoding="utf-8"
            )

        self.assertTrue(result.success)
        call = _FakeCompletions.calls[0]
        self.assertEqual(
            call["messages"],
            [
                {"role": "system", "content": _FakeRefiner.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": "ORIGINAL TEMPLATE|0|target|ghidra|False|"
                    "int target(void) { broken }",
                },
            ],
        )
        self.assertEqual(metadata["prompt_policy"], "runtime_import_from_agent4decompile")
        self.assertFalse(metadata["oracle_assisted"])
        self.assertEqual(saved_system_prompt, _FakeRefiner.SYSTEM_PROMPT)

    def test_constraint_evaluator_compiles_public_context_to_object(self):
        commands: list[list[str]] = []
        sources: list[str] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            source = next(Path(item) for item in command if str(item).endswith(".c"))
            sources.append(source.read_text(encoding="utf-8"))
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.agent4decompile_backend.subprocess.run", side_effect=fake_run
        ):
            evaluator = FrameworkConstraintEvaluator(
                self._request(), Path(temporary), timeout=10, optimization="same"
            )
            result = evaluator.evaluate_all("int target(void) { return 1; }")

        self.assertTrue(result["syntax"]["pass"])
        self.assertTrue(result["compilation"]["pass"])
        self.assertIn("-fsyntax-only", commands[0])
        self.assertIn("-c", commands[1])
        self.assertIn("-O2", commands[1])
        self.assertNotIn("-lm", commands[1])
        self.assertTrue(all("#include <stdint.h>" in source for source in sources))

    def test_benchmark_oracle_constraint_level_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.agent4decompile_backend._import_agent4",
            return_value=(_FakeRefiner, _FakePipeline, _preprocess),
        ):
            with self.assertRaisesRegex(ValueError, "constraint_level must be 1 or 2"):
                Agent4DecompileBackend(
                    self._backend_config(Path(temporary), constraint_level=3)
                )

    def test_evaluator_fails_closed_if_tests_are_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            evaluator = FrameworkConstraintEvaluator(
                self._request(), Path(temporary), timeout=10, optimization="same"
            )
            with self.assertRaisesRegex(ValueError, "must not receive evaluation test data"):
                evaluator.evaluate_all("int target(void) { return 1; }", test_cases=[])


if __name__ == "__main__":
    unittest.main()
