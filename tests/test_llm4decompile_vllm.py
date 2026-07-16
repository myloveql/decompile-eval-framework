from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from decomp_eval.models import AssemblyInput, DecompileRequest, PseudocodeInput
from plugins.llm4decompile_backend import LLM4DecompileBackend


class _FakeTokenizer:
    eos_token = "<eos>"
    eos_token_id = 2
    pad_token_id = None
    padding_side = "right"


class _FakeSamplingParams:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeLLM:
    instances = []
    output_texts = []

    def __init__(self, **kwargs):
        self.options = kwargs
        self.calls = []
        self.__class__.instances.append(self)

    def generate(self, prompts, sampling_params, use_tqdm=True):
        self.calls.append((prompts, sampling_params, use_tqdm))
        texts = self.output_texts or ["int target(void) { return 7; }"] * len(prompts)
        return [
            SimpleNamespace(outputs=[SimpleNamespace(text=text)])
            for text in texts[: len(prompts)]
        ]


class _FakeTransformersModel:
    def __init__(self):
        self.config = SimpleNamespace(use_cache=False)
        self.device = None

    def to(self, device):
        self.device = device
        return self

    def eval(self):
        return self


class LLM4DecompileVLLMTests(unittest.TestCase):
    def setUp(self):
        _FakeLLM.instances.clear()
        _FakeLLM.output_texts = []

    @staticmethod
    def _request(index: int) -> DecompileRequest:
        return DecompileRequest(
            dataset_id="fixture",
            split="test",
            sample_id=f"sample-{index}",
            source_group_id=f"group-{index}",
            function_name=f"target_{index}",
            language="c",
            optimization="O2",
            assembly=AssemblyInput(
                text=f"target_{index}:\n  mov $7, %eax\n  ret",
                syntax="AT&T",
                view="asm",
            ),
            metadata={},
        )

    def _backend(self, model_path: Path, **overrides) -> LLM4DecompileBackend:
        fake_vllm = SimpleNamespace(LLM=_FakeLLM, SamplingParams=_FakeSamplingParams)
        config = {
            "model_path": str(model_path),
            "engine": "vllm",
            "tensor_parallel_size": 2,
            "max_num_seqs": 8,
            "gpu_memory_utilization": 0.82,
            "max_model_len": 64,
            "max_input_tokens": 50,
            "max_new_tokens": 20,
            "do_sample": False,
            "temperature": 0.8,
            "use_tqdm": False,
            **overrides,
        }
        with patch.dict(sys.modules, {"vllm": fake_vllm}), patch(
            "plugins.llm4decompile_backend.AutoTokenizer.from_pretrained",
            return_value=_FakeTokenizer(),
        ):
            return LLM4DecompileBackend(config)

    def test_vllm_batch_generation_preserves_order_and_configuration(self):
        _FakeLLM.output_texts = [
            "int target_0(void) { return 7; }",
            "int target_1(void) { return 8; }",
        ]
        with tempfile.TemporaryDirectory() as temp:
            backend = self._backend(Path(temp))
            results = backend.decompile_many(
                [self._request(0), self._request(1)],
                [Path(temp) / "a", Path(temp) / "b"],
            )
        self.assertEqual([result.code for result in results], _FakeLLM.output_texts)
        self.assertTrue(all(result.success for result in results))
        llm = _FakeLLM.instances[-1]
        self.assertEqual(llm.options["tensor_parallel_size"], 2)
        self.assertEqual(llm.options["max_model_len"], 64)
        self.assertEqual(llm.options["max_num_seqs"], 8)
        prompts, sampling, use_tqdm = llm.calls[0]
        self.assertEqual(len(prompts), 2)
        self.assertIn("# This is the assembly code:", prompts[0])
        self.assertEqual(sampling.temperature, 0.0)
        self.assertEqual(sampling.max_tokens, 20)
        self.assertEqual(sampling.truncate_prompt_tokens, 44)
        self.assertEqual(sampling.stop, ["<eos>"])
        self.assertFalse(use_tqdm)

    def test_vllm_empty_generation_is_a_fixed_denominator_failure(self):
        _FakeLLM.output_texts = [""]
        with tempfile.TemporaryDirectory() as temp:
            backend = self._backend(Path(temp))
            result = backend.decompile(self._request(0), Path(temp))
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "empty_model_output")
        self.assertEqual(result.backend_version, "llm4decompile-1.3b-v1.6:vllm")

    def test_pseudocode_uses_the_unchanged_llm4decompile_prompt(self):
        request = replace(
            self._request(0),
            assembly=AssemblyInput(text="", syntax="AT&T", view="asm"),
            pseudocode=PseudocodeInput(
                text="int func0(void) { return 7; }",
                view="ghidra_pseudo",
                producer="ghidra",
            ),
        )
        with tempfile.TemporaryDirectory() as temp:
            backend = self._backend(Path(temp))
            prompt = backend.build_prompt(request)
            result = backend.decompile(request, Path(temp))
        self.assertTrue(result.success)
        self.assertEqual(
            prompt,
            "# This is the assembly code:\n"
            "int func0(void) { return 7; }\n"
            "# What is the source code?\n",
        )
        sent_prompt = _FakeLLM.instances[-1].calls[0][0][0]
        self.assertEqual(sent_prompt, prompt)

    def test_assembly_remains_preferred_when_both_views_are_available(self):
        request = replace(
            self._request(0),
            pseudocode=PseudocodeInput(
                text="int pseudo(void);", view="ghidra_pseudo", producer="ghidra"
            ),
        )
        with tempfile.TemporaryDirectory() as temp:
            backend = self._backend(Path(temp))
            prompt = backend.build_prompt(request)
        self.assertIn("mov $7, %eax", prompt)
        self.assertNotIn("int pseudo", prompt)

    def test_vllm_rejects_impossible_token_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "max_model_len"):
                self._backend(Path(temp), max_model_len=20, max_new_tokens=20)

    def test_transformers_remains_the_default_engine(self):
        fake_model = _FakeTransformersModel()
        with tempfile.TemporaryDirectory() as temp, patch(
            "plugins.llm4decompile_backend.AutoTokenizer.from_pretrained",
            return_value=_FakeTokenizer(),
        ), patch(
            "plugins.llm4decompile_backend.AutoModelForCausalLM.from_pretrained",
            return_value=fake_model,
        ):
            backend = LLM4DecompileBackend({"model_path": temp, "device": "cpu"})
        self.assertEqual(backend.engine, "transformers")
        self.assertEqual(backend.version, "llm4decompile-1.3b-v1.6")
        self.assertEqual(fake_model.device, "cpu")
        self.assertTrue(fake_model.config.use_cache)


if __name__ == "__main__":
    unittest.main()
