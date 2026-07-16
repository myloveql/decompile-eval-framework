from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from decomp_eval.models import AssemblyInput, CandidateCompileContext, DecompileRequest
from plugins.sccdec_backend import SCCDecBackend


class _FakeCompletions:
    outputs: list[str] = []
    calls: list[dict] = []

    def create(self, **kwargs):
        self.__class__.calls.append(kwargs)
        text = self.__class__.outputs.pop(0)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


class _FakeOpenAI:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.chat = SimpleNamespace(completions=_FakeCompletions())
        self.closed = False

    def close(self):
        self.closed = True


class SCCDecBackendTests(unittest.TestCase):
    def setUp(self):
        _FakeCompletions.outputs = []
        _FakeCompletions.calls = []

    @staticmethod
    def _request(*, language: str = "c", with_context: bool = True):
        return DecompileRequest(
            dataset_id="fixture",
            split="test",
            sample_id="fixture:0:O2",
            source_group_id="fixture:0",
            function_name="func0",
            language=language,
            optimization="O2",
            assembly=AssemblyInput(
                text="<func0>:\nmov $7, %eax\nret", syntax="att", view="asm"
            ),
            metadata={},
            compile_context=(
                CandidateCompileContext(
                    language="c",
                    compiler="gcc",
                    flags=("-std=gnu11", "-w"),
                    libraries=("-lm",),
                    prelude="#include <stdint.h>\ntypedef uint32_t u32;",
                )
                if with_context
                else None
            ),
        )

    @staticmethod
    def _backend(**overrides):
        config = {
            "base_url": "http://127.0.0.1:8000/v1",
            "model": "sccdec",
            "api_key": "test-only",
            "mode": "scc",
            "max_retries": 1,
            "retry_backoff": 0,
            **overrides,
        }
        with patch.dict(sys.modules, {"openai": SimpleNamespace(OpenAI=_FakeOpenAI)}):
            return SCCDecBackend(config)

    def test_scc_two_stage_inference_uses_recompiled_candidate(self):
        _FakeCompletions.outputs = [
            "```c\nint func0(void) { return 7; }\n```",
            "int func0(void) { return 8; }",
        ]
        compile_sources: list[str] = []

        def fake_run(command, **kwargs):
            if command[0] == "gcc":
                source = next(Path(arg) for arg in command if str(arg).endswith(".c"))
                compile_sources.append(source.read_text(encoding="utf-8"))
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(
                command,
                0,
                "0000000000001100 <func0>:\n"
                "    1100:\tb8 07 00 00 00       \tmov    $0x7,%eax\n"
                "    1105:\tc3                   \tret\n",
                "",
            )

        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.sccdec_backend.subprocess.run", side_effect=fake_run
        ):
            artifact_dir = Path(temporary)
            result = self._backend().decompile(self._request(), artifact_dir)
            metadata = json.loads(
                (artifact_dir / "sccdec_metadata.json").read_text(encoding="utf-8")
            )
            second_messages = json.loads(
                (artifact_dir / "sccdec_second_messages.json").read_text(encoding="utf-8")
            )

        self.assertTrue(result.success)
        self.assertIn("return 8", result.code)
        self.assertTrue(metadata["scc_applied"])
        self.assertEqual(metadata["final_stage"], "scc")
        self.assertIn("#include <stdint.h>", compile_sources[0])
        self.assertIn("int func0(void) { return 7; }", compile_sources[0])
        self.assertIn("mov    $0x7,%eax", second_messages[0]["content"])
        self.assertEqual(second_messages[1]["role"], "assistant")
        self.assertEqual(len(_FakeCompletions.calls), 2)

    def test_compile_failure_falls_back_to_first_candidate(self):
        _FakeCompletions.outputs = ["int func0(void) { return 7; }"]
        failed = subprocess.CompletedProcess(["gcc"], 1, "", "syntax error")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.sccdec_backend.subprocess.run", return_value=failed
        ):
            artifact_dir = Path(temporary)
            result = self._backend().decompile(self._request(), artifact_dir)
            metadata = json.loads(
                (artifact_dir / "sccdec_metadata.json").read_text(encoding="utf-8")
            )
        self.assertTrue(result.success)
        self.assertIn("return 7", result.code)
        self.assertFalse(metadata["scc_applied"])
        self.assertEqual(metadata["fallback_reason"], "compile_error")
        self.assertEqual(len(_FakeCompletions.calls), 1)

    def test_fae_mode_skips_self_context_compilation(self):
        _FakeCompletions.outputs = ["int func0(void) { return 7; }"]
        with tempfile.TemporaryDirectory() as temporary, patch(
            "plugins.sccdec_backend.subprocess.run"
        ) as run:
            result = self._backend(mode="fae").decompile(
                self._request(with_context=False), Path(temporary)
            )
        self.assertTrue(result.success)
        self.assertFalse(run.called)

    def test_cplusplus_is_rejected_without_calling_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self._backend().decompile(
                self._request(language="cpp"), Path(temporary)
            )
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "sccdec_unsupported_language")
        self.assertEqual(_FakeCompletions.calls, [])

    def test_one_shot_prepare_adds_fixed_example(self):
        _FakeCompletions.outputs = ["int func0(void) { return 7; }"]
        backend = self._backend(mode="fae", one_shot=True)
        with patch.object(
            backend,
            "_build_scc_context",
            return_value=("<func0>:\nmov $1, %eax\nret", {"outcome": "success"}),
        ):
            backend.prepare([self._request()])
        with tempfile.TemporaryDirectory() as temporary:
            result = backend.decompile(self._request(), Path(temporary))
        self.assertTrue(result.success)
        messages = _FakeCompletions.calls[0]["messages"]
        self.assertEqual([message["role"] for message in messages], ["user", "assistant", "user"])
        self.assertIn("bool func0(int num)", messages[1]["content"])


if __name__ == "__main__":
    unittest.main()
