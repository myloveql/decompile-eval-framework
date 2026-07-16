from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from plugins.openai_compatible_backend import (
    OpenAICompatibleBackend,
    extract_candidate_code,
)
from decomp_eval.models import AssemblyInput, CanonicalSample, PseudocodeInput
from decomp_eval.util import redact


class _FakeOpenAI:
    instances = []
    response_text = ""
    response_texts = []
    reasoning_content = None

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
        text = self.response_texts.pop(0) if self.response_texts else self.response_text
        return SimpleNamespace(
            id="resp-test",
            status="completed",
            output_text=text,
            usage=SimpleNamespace(model_dump=lambda: {"input_tokens": 10, "output_tokens": 5}),
        )

    def _chat_create(self, **kwargs):
        self.calls.append(("chat_completions", kwargs))
        text = self.response_texts.pop(0) if self.response_texts else self.response_text
        return SimpleNamespace(
            id="chat-test",
            choices=[SimpleNamespace(
                finish_reason="stop",
                message=SimpleNamespace(
                    content=text,
                    reasoning_content=self.reasoning_content,
                ),
            )],
            usage=SimpleNamespace(model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 5}),
        )

    def close(self):
        return None


class OpenAIBackendTests(unittest.TestCase):
    def setUp(self):
        _FakeOpenAI.instances.clear()
        _FakeOpenAI.response_text = ""
        _FakeOpenAI.response_texts = []
        _FakeOpenAI.reasoning_content = None

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
            "provider": "compatible-vendor",
            "base_url": "https://llm.example.test/v1",
            "model": "vendor-model",
            "api_key_env": "TEST_CLOSED_LLM_KEY",
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
        request = self._sample().public_request(("pseudocode",))
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
            user_prompt_template="Recover {function_name} from:\n{assembly}",
        )
        request = self._sample().public_request(("assembly",))
        with tempfile.TemporaryDirectory() as temp:
            result = backend.decompile(request, Path(temp))
        self.assertTrue(result.success)
        mode, call = _FakeOpenAI.instances[-1].calls[0]
        self.assertEqual(mode, "chat_completions")
        self.assertIn("Recover target", call["messages"][1]["content"])
        self.assertIn("mov eax, 7", call["messages"][1]["content"])
        self.assertEqual(call["max_tokens"], 4096)

    def test_empty_output_is_retried_and_attempts_are_audited(self):
        _FakeOpenAI.response_texts = ["", "   ", "```c\nint target(void) { return 7; }\n```"]
        backend = self._prepared_backend(
            api_mode="chat_completions",
            empty_output_retries=2,
            empty_output_backoff_seconds=0,
        )
        request = self._sample().public_request(("assembly",))
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp)
            result = backend.decompile(request, artifact_dir)
            metadata = json.loads(
                (artifact_dir / "response_metadata.json").read_text(encoding="utf-8")
            )
        self.assertTrue(result.success)
        self.assertEqual(len(_FakeOpenAI.instances[-1].calls), 3)
        self.assertEqual(metadata["attempt_count"], 3)
        self.assertEqual(
            [attempt["outcome"] for attempt in metadata["attempts"]],
            ["empty_output", "empty_output", "success"],
        )

    def test_empty_output_failure_after_retry_budget_is_exhausted(self):
        _FakeOpenAI.response_texts = ["", ""]
        backend = self._prepared_backend(
            empty_output_retries=1,
            empty_output_backoff_seconds=0,
        )
        request = self._sample().public_request(("assembly",))
        with tempfile.TemporaryDirectory() as temp:
            result = backend.decompile(request, Path(temp))
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "closed_llm_empty_output")
        self.assertIn("after 2 attempts", result.log)

    def test_missing_key_is_clear_and_literal_key_is_redacted(self):
        backend = OpenAICompatibleBackend({
            "id": "missing", "model": "model",
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
                "id": "vendor", "provider": "vendor", "model": "m"
            })

    def test_disabled_thinking_is_sent_in_extra_body_and_audited(self):
        _FakeOpenAI.response_text = "int target(void) { return 7; }"
        _FakeOpenAI.reasoning_content = "unexpected reasoning"
        backend = self._prepared_backend(
            api_mode="chat_completions",
            thinking_mode="disabled",
            thinking_protocol="thinking_type",
            extra_body={"top_k": 20},
        )
        request = self._sample().public_request(("assembly",))
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp)
            result = backend.decompile(request, artifact_dir)
            metadata = json.loads(
                (artifact_dir / "response_metadata.json").read_text(encoding="utf-8")
            )
        self.assertTrue(result.success)
        _, call = _FakeOpenAI.instances[-1].calls[0]
        self.assertEqual(
            call["extra_body"],
            {"top_k": 20, "thinking": {"type": "disabled"}},
        )
        self.assertEqual(metadata["thinking_mode"], "disabled")
        self.assertTrue(metadata["reasoning_content_present"])
        self.assertEqual(metadata["reasoning_content_chars"], 20)

    def test_auto_thinking_does_not_add_extra_body(self):
        backend = self._prepared_backend(
            api_mode="chat_completions",
            thinking_mode="auto",
        )
        backend._infer("prompt")
        _, call = _FakeOpenAI.instances[-1].calls[0]
        self.assertNotIn("extra_body", call)

    def test_thinking_configuration_conflict_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self._prepared_backend(
                thinking_mode="disabled",
                thinking_protocol="thinking_type",
                extra_body={"thinking": {"type": "enabled"}},
            )

    def test_kimi_k27_rejects_non_auto_thinking_mode(self):
        with self.assertRaisesRegex(ValueError, "always-thinking"):
            OpenAICompatibleBackend({
                "provider": "kimi",
                "base_url": "https://api.moonshot.cn/v1",
                "model": "kimi-k2.7-code-highspeed",
                "thinking_mode": "disabled",
            })

    def test_kimi_k26_allows_disabled_thinking(self):
        config = {
            "provider": "kimi",
            "base_url": "https://api.moonshot.cn/v1",
            "model": "kimi-k2.6",
            "thinking_mode": "disabled",
            "extra_body": {"thinking": {"keep": "all"}},
        }
        backend = OpenAICompatibleBackend(config)
        self.assertEqual(
            backend.extra_body,
            {"thinking": {"keep": "all", "type": "disabled"}},
        )
        self.assertEqual(config["extra_body"], {"thinking": {"keep": "all"}})

    def test_unknown_provider_requires_explicit_thinking_protocol(self):
        with self.assertRaisesRegex(ValueError, "no built-in thinking protocol"):
            self._prepared_backend(thinking_mode="disabled")

    def test_custom_thinking_payload_supports_vendor_specific_fields(self):
        backend = self._prepared_backend(
            thinking_mode="disabled",
            thinking_protocol="custom",
            thinking_payload={"enable_thinking": False},
            extra_body={"top_k": 10},
        )
        self.assertEqual(
            backend.extra_body,
            {"top_k": 10, "enable_thinking": False},
        )


if __name__ == "__main__":
    unittest.main()
