from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from decomp_eval.backends.openai_compatible import (
    OpenAICompatibleBackend,
    extract_candidate_code,
)
from decomp_eval.models import AssemblyInput, CanonicalSample, PseudocodeInput
from decomp_eval.util import redact


class _FakeOpenAI:
    instances = []
    response_text = ""

    def __init__(self, **kwargs):
        self.options = kwargs
        self.calls = []
        self.responses = SimpleNamespace(create=self._responses_create)
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._chat_create)
        )
        self.__class__.instances.append(self)

    def _responses_create(self, **kwargs):
        self.calls.append(("responses", kwargs))
        return SimpleNamespace(
            id="resp-test",
            status="completed",
            output_text=self.response_text,
            usage=SimpleNamespace(model_dump=lambda: {"input_tokens": 10, "output_tokens": 5}),
        )

    def _chat_create(self, **kwargs):
        self.calls.append(("chat_completions", kwargs))
        return SimpleNamespace(
            id="chat-test",
            choices=[SimpleNamespace(
                finish_reason="stop",
                message=SimpleNamespace(content=self.response_text),
            )],
            usage=SimpleNamespace(model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 5}),
        )

    def close(self):
        return None


class OpenAIBackendTests(unittest.TestCase):
    def setUp(self):
        _FakeOpenAI.instances.clear()

    @staticmethod
    def _sample() -> CanonicalSample:
        return CanonicalSample(
            "dataset", "benchmark", "sample", "group", "target", "c", "O2",
            AssemblyInput("target:\n  mov eax, 7\n  ret", "intel", "instruction_only"),
            "hash",
            pseudocode=PseudocodeInput(
                "int target(void) { return 7; }", "ghidra", "ghidra", "11.0.3"
            ),
        )

    def _prepared_backend(self, **overrides):
        config = {
            "id": "closed-model",
            "type": "openai",
            "provider": "compatible-vendor",
            "base_url": "https://llm.example.test/v1",
            "model": "vendor-model",
            "api_key_env": "TEST_CLOSED_LLM_KEY",
            "required_inputs": ["pseudocode"],
            **overrides,
        }
        backend = OpenAICompatibleBackend(config)
        fake_module = SimpleNamespace(OpenAI=_FakeOpenAI)
        with patch.dict(sys.modules, {"openai": fake_module}), patch.dict(
            os.environ, {"TEST_CLOSED_LLM_KEY": "super-secret"}, clear=False
        ):
            backend.prepare([])
        return backend

    def test_extracts_longest_c_fence(self):
        code, method = extract_candidate_code(
            "Explanation\n```text\nshort\n```\n```cpp\nint target(void) { return 7; }\n```"
        )
        self.assertEqual(code, "int target(void) { return 7; }")
        self.assertEqual(method, "longest_c_fence")

    def test_responses_api_uses_only_configured_public_input(self):
        _FakeOpenAI.response_text = "Analysis first.\n```c\nint target(void) { return 7; }\n```"
        backend = self._prepared_backend(api_mode="responses")
        request = self._sample().public_request(backend.required_inputs)
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp)
            result = backend.decompile(request, artifact_dir)
            metadata = json.loads(
                (artifact_dir / "response_metadata.json").read_text(encoding="utf-8")
            )
        self.assertTrue(result.success)
        self.assertEqual(result.code, "int target(void) { return 7; }")
        self.assertIn("Analysis first", result.raw_output)
        client = _FakeOpenAI.instances[-1]
        self.assertEqual(client.options["api_key"], "super-secret")
        _, call = client.calls[0]
        self.assertIn("Existing pseudocode", call["input"])
        self.assertNotIn("Assembly (", call["input"])
        self.assertEqual(metadata["extraction"], "longest_c_fence")
        self.assertNotIn("super-secret", json.dumps(metadata))

    def test_chat_completions_and_prompt_template(self):
        _FakeOpenAI.response_text = "int target(void) { return 7; }"
        backend = self._prepared_backend(
            api_mode="chat_completions",
            required_inputs=["assembly"],
            user_prompt_template="Recover {function_name} from:\n{assembly}",
        )
        request = self._sample().public_request(backend.required_inputs)
        with tempfile.TemporaryDirectory() as temp:
            result = backend.decompile(request, Path(temp))
        self.assertTrue(result.success)
        mode, call = _FakeOpenAI.instances[-1].calls[0]
        self.assertEqual(mode, "chat_completions")
        self.assertIn("Recover target", call["messages"][1]["content"])
        self.assertIn("mov eax, 7", call["messages"][1]["content"])
        self.assertEqual(call["max_tokens"], 4096)

    def test_missing_key_is_clear_and_literal_key_is_redacted(self):
        backend = OpenAICompatibleBackend({
            "id": "missing", "type": "openai", "model": "model",
            "api_key_env": "DEFINITELY_MISSING_LLM_KEY",
        })
        fake_module = SimpleNamespace(OpenAI=_FakeOpenAI)
        with patch.dict(sys.modules, {"openai": fake_module}), patch.dict(
            os.environ, {}, clear=True
        ):
            with self.assertRaisesRegex(RuntimeError, "DEFINITELY_MISSING_LLM_KEY"):
                backend.prepare([])
        value = redact({"decompilers": [{"api_key": "do-not-persist", "model": "m"}]})
        self.assertEqual(value["decompilers"][0]["api_key"], "<redacted>")

    def test_provider_requires_base_url(self):
        with self.assertRaisesRegex(ValueError, "base_url"):
            OpenAICompatibleBackend({
                "id": "vendor", "type": "openai", "provider": "vendor", "model": "m"
            })


if __name__ == "__main__":
    unittest.main()
