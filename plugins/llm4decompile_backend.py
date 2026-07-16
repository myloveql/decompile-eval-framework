"""LLM4Decompile backend with Transformers and vLLM inference engines."""

from __future__ import annotations

import argparse
import gc
import json
import time
from dataclasses import asdict
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from decomp_eval.models import AssemblyInput, DecompileRequest, DecompileResult


class LLM4DecompileBackend:
    version = "llm4decompile-1.3b-v1.6"

    def __init__(self, config):
        self.config = dict(config)
        self.model_path = Path(config["model_path"]).expanduser().resolve()
        self.engine = str(config.get("engine", "transformers")).lower()
        if self.engine not in {"transformers", "vllm"}:
            raise ValueError("engine must be transformers or vllm")
        self.version = (
            f"{type(self).version}:vllm" if self.engine == "vllm" else type(self).version
        )
        if not self.model_path.is_dir():
            raise ValueError(f"model_path is not a directory: {self.model_path}")
        self.device = config.get(
            "device", "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.max_new_tokens = int(config.get("max_new_tokens", 4096))
        self.max_input_tokens = int(config.get("max_input_tokens", 32768))
        self.do_sample = bool(config.get("do_sample", False))
        self.temperature = float(config.get("temperature", 0.0))
        self.top_p = float(config.get("top_p", 1.0))
        self.top_k = int(config.get("top_k", -1))
        self.repetition_penalty = float(config.get("repetition_penalty", 1.0))
        self.seed = int(config.get("seed", 0))
        self.use_tqdm = bool(config.get("use_tqdm", False))

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_path,
            trust_remote_code=False,
        )
        self.tokenizer.padding_side = "left"
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

        if self.engine == "vllm":
            self._init_vllm(config)
        else:
            self._init_transformers()

    def _init_transformers(self) -> None:
        dtype = self._choose_dtype()
        print(f"Loading {self.model_path} with Transformers on {self.device} using {dtype}")
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_path,
            torch_dtype=dtype,
            trust_remote_code=False,
        ).to(self.device)
        self.model.eval()
        self.model.config.use_cache = True

    def _init_vllm(self, config) -> None:
        try:
            from vllm import LLM, SamplingParams
        except ImportError as error:
            raise RuntimeError(
                "vLLM is required for engine=vllm; install with: pip install -e '.[vllm]'"
            ) from error

        self.tensor_parallel_size = max(
            1, int(config.get("tensor_parallel_size", config.get("gpus", 1)))
        )
        self.gpu_memory_utilization = float(config.get("gpu_memory_utilization", 0.82))
        self.max_model_len = int(
            config.get(
                "max_model_len",
                config.get("max_total_tokens", self.max_input_tokens + self.max_new_tokens),
            )
        )
        if self.max_model_len <= self.max_new_tokens:
            raise ValueError("max_model_len must be greater than max_new_tokens")
        self.max_num_seqs = max(1, int(config.get("max_num_seqs", 8)))
        max_prompt_tokens = min(
            self.max_input_tokens,
            self.max_model_len - self.max_new_tokens,
        )
        llm_options = {
            "model": str(self.model_path),
            "tensor_parallel_size": self.tensor_parallel_size,
            "max_model_len": self.max_model_len,
            "max_num_seqs": self.max_num_seqs,
            "gpu_memory_utilization": self.gpu_memory_utilization,
            "dtype": config.get("dtype", "auto"),
            "seed": self.seed,
            "trust_remote_code": False,
            **dict(config.get("vllm_kwargs", {})),
        }
        print(
            f"Loading {self.model_path} with vLLM using "
            f"tensor_parallel_size={self.tensor_parallel_size}, "
            f"max_model_len={self.max_model_len}"
        )
        self.model = LLM(**llm_options)
        stop = config.get("stop")
        if stop is None and self.tokenizer.eos_token:
            stop = [self.tokenizer.eos_token]
        sampling_temperature = self.temperature if self.do_sample else 0.0
        self.sampling_params = SamplingParams(
            temperature=sampling_temperature,
            top_p=self.top_p if self.do_sample else 1.0,
            top_k=self.top_k if self.do_sample else -1,
            repetition_penalty=self.repetition_penalty,
            max_tokens=self.max_new_tokens,
            stop=stop,
            seed=self.seed,
            truncate_prompt_tokens=max_prompt_tokens,
        )

    def _choose_dtype(self):
        if self.device == "cpu":
            return torch.float32
        if self.device.startswith("cuda") and torch.cuda.is_bf16_supported():
            return torch.bfloat16
        return torch.float16

    def prepare(self, requests):
        """可选的模型预热。"""
        if not requests or self.engine == "vllm":
            return

        warmup_prompt = (
            "# This is the assembly code:\n"
            "test:\n"
            "  xor eax, eax\n"
            "  ret\n"
            "# What is the source code?\n"
        )

        inputs = self.tokenizer(
            warmup_prompt,
            return_tensors="pt",
        ).to(self.device)

        with torch.inference_mode():
            self.model.generate(
                **inputs,
                max_new_tokens=8,
                do_sample=False,
            )

    def build_prompt(self, request: DecompileRequest) -> str:
        # Keep the exact LLM4Decompile training prompt for both supported
        # representations. required_inputs decides which public field survives.
        assembly = request.assembly.text.strip()
        pseudocode = (
            request.pseudocode.text.strip()
            if request.pseudocode is not None
            else ""
        )
        if assembly:
            model_input = assembly
        elif pseudocode:
            model_input = pseudocode
        else:
            raise ValueError("LLM4Decompile requires non-empty assembly or pseudocode input")
        return (
            "# This is the assembly code:\n"
            f"{model_input}\n"
            "# What is the source code?\n"
        )

    def _generation_kwargs(self):
        values = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": self.do_sample,
            "pad_token_id": self.tokenizer.pad_token_id,
            "eos_token_id": self.tokenizer.eos_token_id,
        }

        if self.do_sample:
            values.update(
                {
                    "temperature": self.temperature,
                    "top_p": self.top_p,
                }
            )

        return values

    def decompile(
        self,
        request: DecompileRequest,
        artifact_dir: Path,
    ) -> DecompileResult:
        if self.engine == "vllm":
            return self._decompile_many_vllm([request])[0]

        started = time.perf_counter()

        try:
            prompt = self.build_prompt(request)
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_input_tokens,
            ).to(self.device)

            input_width = inputs["input_ids"].shape[1]

            with torch.inference_mode():
                output = self.model.generate(
                    **inputs,
                    **self._generation_kwargs(),
                )

            generated_tokens = output[0, input_width:]
            code = self.tokenizer.decode(
                generated_tokens,
                skip_special_tokens=True,
            ).strip()

            return DecompileResult(
                success=bool(code),
                raw_output=code,
                code=code,
                reason=None if code else "empty_model_output",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        except torch.cuda.OutOfMemoryError as error:
            torch.cuda.empty_cache()
            return DecompileResult(
                success=False,
                reason="cuda_out_of_memory",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        except Exception as error:
            return DecompileResult(
                success=False,
                reason="model_inference_error",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

    def decompile_many(self, requests, artifact_dirs):
        """批量推理；返回结果数量必须与请求数量完全一致。"""
        if not requests:
            return []
        if self.engine == "vllm":
            return self._decompile_many_vllm(requests)

        started = time.perf_counter()
        prompts = [self.build_prompt(request) for request in requests]

        try:
            inputs = self.tokenizer(
                prompts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=self.max_input_tokens,
            ).to(self.device)

            input_width = inputs["input_ids"].shape[1]

            with torch.inference_mode():
                outputs = self.model.generate(
                    **inputs,
                    **self._generation_kwargs(),
                )

            elapsed = time.perf_counter() - started
            per_sample_elapsed = elapsed / len(requests)
            results = []

            for output in outputs:
                generated_tokens = output[input_width:]
                code = self.tokenizer.decode(
                    generated_tokens,
                    skip_special_tokens=True,
                ).strip()

                results.append(
                    DecompileResult(
                        success=bool(code),
                        raw_output=code,
                        code=code,
                        reason=None if code else "empty_model_output",
                        elapsed_seconds=per_sample_elapsed,
                        backend_version=self.version,
                    )
                )

            return results

        except torch.cuda.OutOfMemoryError as error:
            torch.cuda.empty_cache()
            return [
                DecompileResult(
                    success=False,
                    reason="cuda_out_of_memory",
                    log=repr(error),
                    backend_version=self.version,
                )
                for _ in requests
            ]

        except Exception as error:
            return [
                DecompileResult(
                    success=False,
                    reason="model_batch_inference_error",
                    log=repr(error),
                    backend_version=self.version,
                )
                for _ in requests
            ]

    def _decompile_many_vllm(self, requests):
        started = time.perf_counter()
        prompts = [self.build_prompt(request) for request in requests]
        try:
            outputs = self.model.generate(
                prompts,
                self.sampling_params,
                use_tqdm=self.use_tqdm,
            )
            if len(outputs) != len(requests):
                raise ValueError(
                    f"vLLM returned {len(outputs)} outputs for {len(requests)} prompts"
                )
            elapsed = time.perf_counter() - started
            per_sample_elapsed = elapsed / len(requests)
            results = []
            for output in outputs:
                candidates = getattr(output, "outputs", None) or []
                code = str(getattr(candidates[0], "text", "") if candidates else "").strip()
                results.append(
                    DecompileResult(
                        success=bool(code),
                        raw_output=code,
                        code=code,
                        reason=None if code else "empty_model_output",
                        elapsed_seconds=per_sample_elapsed,
                        backend_version=self.version,
                    )
                )
            return results
        except torch.cuda.OutOfMemoryError as error:
            torch.cuda.empty_cache()
            return [
                DecompileResult(
                    success=False,
                    reason="cuda_out_of_memory",
                    log=repr(error),
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
                for _ in requests
            ]
        except Exception as error:
            return [
                DecompileResult(
                    success=False,
                    reason="vllm_inference_error",
                    log=repr(error),
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
                for _ in requests
            ]

    def close(self):
        if hasattr(self, "model"):
            del self.model
        if self.engine == "vllm":
            try:
                from vllm.distributed.parallel_state import (
                    destroy_distributed_environment,
                    destroy_model_parallel,
                )

                destroy_model_parallel()
                destroy_distributed_environment()
            except (ImportError, RuntimeError):
                pass
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()


def build_request_from_exebench(
    dataset_path: Path,
    *,
    optimization: str = "O0",
    sample_index: int = 0,
    sample_id: str | None = None,
    assembly_view: str = "objdump_att_instruction_only",
) -> DecompileRequest:
    """Read one flat ExeBench record and expose only public decompiler fields."""
    document = json.loads(dataset_path.read_text(encoding="utf-8"))
    samples = document["samples"]

    if sample_id:
        try:
            row = next(item for item in samples if item["sample_id"] == sample_id)
        except StopIteration as error:
            raise ValueError(f"sample_id not found: {sample_id}") from error
    else:
        candidates = [
            item for item in samples
            if item.get("optimization") == optimization
        ]
        if not candidates:
            raise ValueError(f"no samples found for optimization {optimization}")
        if sample_index < 0 or sample_index >= len(candidates):
            raise IndexError(
                f"sample_index {sample_index} is outside [0, {len(candidates) - 1}]"
            )
        row = candidates[sample_index]

    assembly_record = row.get("assembly", {})
    assembly_text = assembly_record.get(assembly_view, "")
    if not assembly_text.strip():
        raise ValueError(
            f"sample {row['sample_id']} has no assembly in view {assembly_view}"
        )

    return DecompileRequest(
        dataset_id=document.get("dataset_id", "exebench-1100"),
        split="benchmark",
        sample_id=row["sample_id"],
        source_group_id=row["source_group_id"],
        function_name=row["function_name"],
        language=row.get("source_metadata", {}).get("language", "c"),
        optimization=row["optimization"],
        assembly=AssemblyInput(
            text=assembly_text,
            syntax=(
                assembly_record.get(f"{assembly_view}_syntax")
                or ("Intel" if assembly_view.startswith("objdump_intel") else assembly_record.get("syntax", "GNU assembler AT&T"))
            ),
            view=assembly_view,
        ),
        metadata={
            "source_type": row.get("source_type"),
            "signature": row.get("source", {}).get("signature", []),
            "assembly_origin": assembly_record.get("origin"),
            "assembly_available": True,
        },
    )


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run LLM4DecompileBackend on one ExeBench sample."
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=project_root / "models" / "llm4decompile-1.3b-v1.6",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=(
            project_root
            / "datasets"
            / "exebench-1641"
            / "exebench_1641_source_multiopt_1100.dataset.json"
        ),
    )
    parser.add_argument("--optimization", choices=("O0", "O1", "O2", "O3"), default="O0")
    parser.add_argument("--sample-index", type=int, default=0)
    parser.add_argument("--sample-id", default=None)
    parser.add_argument(
        "--assembly-view",
        default="objdump_att_instruction_only",
        choices=(
            "objdump_att_instruction_only",
            "objdump_intel_instruction_only",
            "objdump_intel_with_relocations",
            "gcc_target_assembly",
            "full_translation_unit_assembly",
            "upstream_matching_function_assembly",
        ),
    )
    parser.add_argument(
        "--device",
        default="cuda" if torch.cuda.is_available() else "cpu",
    )
    parser.add_argument("--engine", choices=("transformers", "vllm"), default="transformers")
    parser.add_argument("--max-input-tokens", type=int, default=14000)
    parser.add_argument("--max-new-tokens", type=int, default=2048)
    parser.add_argument("--max-model-len", type=int, default=16384)
    parser.add_argument("--tensor-parallel-size", type=int, default=1)
    parser.add_argument("--max-num-seqs", type=int, default=8)
    parser.add_argument("--gpu-memory-utilization", type=float, default=0.82)
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=project_root / "runs" / "backend-smoke",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    request = build_request_from_exebench(
        args.dataset.resolve(),
        optimization=args.optimization,
        sample_index=args.sample_index,
        sample_id=args.sample_id,
        assembly_view=args.assembly_view,
    )

    artifact_dir = args.artifact_dir.resolve() / request.sample_id.replace(":", "_")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "request.json").write_text(
        json.dumps(request.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "assembly.s").write_text(
        request.assembly.text,
        encoding="utf-8",
    )

    print("Constructed DecompileRequest:")
    print(f"  sample_id: {request.sample_id}")
    print(f"  function_name: {request.function_name}")
    print(f"  optimization: {request.optimization}")
    print(f"  language: {request.language}")
    print(f"  assembly_view: {request.assembly.view}")
    print(f"  assembly_chars: {len(request.assembly.text)}")
    print(f"  artifact_dir: {artifact_dir}")

    backend = LLM4DecompileBackend(
        {
            "model_path": str(args.model_path.resolve()),
            "engine": args.engine,
            "device": args.device,
            "max_input_tokens": args.max_input_tokens,
            "max_new_tokens": args.max_new_tokens,
            "max_model_len": args.max_model_len,
            "tensor_parallel_size": args.tensor_parallel_size,
            "max_num_seqs": args.max_num_seqs,
            "gpu_memory_utilization": args.gpu_memory_utilization,
            "do_sample": False,
        }
    )
    try:
        prompt = backend.build_prompt(request)
        (artifact_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
        result = backend.decompile(request, artifact_dir)
    finally:
        backend.close()

    (artifact_dir / "decompile_result.json").write_text(
        json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "candidate.c").write_text(
        result.code or result.raw_output,
        encoding="utf-8",
    )

    print("Decompilation result:")
    print(f"  success: {result.success}")
    print(f"  reason: {result.reason}")
    print(f"  elapsed_seconds: {result.elapsed_seconds:.3f}")
    print(f"  generated_chars: {len(result.code or result.raw_output)}")
    if result.log:
        print(f"  log: {result.log}")
    print(f"  candidate: {artifact_dir / 'candidate.c'}")
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
