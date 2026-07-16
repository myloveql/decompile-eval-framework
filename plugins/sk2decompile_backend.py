"""Two-stage SK2Decompile backend for pseudocode-to-C reconstruction."""

from __future__ import annotations

import gc
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from decomp_eval.models import DecompileRequest, DecompileResult


_TYPEDEF_MAP = {
    "cpu_set_t": "int",
    "nl_item": "int",
    "__time_t": "int",
    "__mode_t": "unsigned short",
    "__off64_t": "long long",
    "__blksize_t": "long",
    "__ino_t": "unsigned long",
    "__blkcnt_t": "unsigned long long",
    "__syscall_slong_t": "long",
    "__ssize_t": "long int",
    "wchar_t": "unsigned short int",
    "wctype_t": "unsigned short int",
    "__int64": "long long",
    "__int32": "int",
    "__int16": "short",
    "__int8": "char",
    "_QWORD": "uint64_t",
    "_OWORD": "long double",
    "_DWORD": "uint32_t",
    "size_t": "unsigned int",
    "_BYTE": "uint8_t",
    "_TBYTE": "uint16_t",
    "_BOOL8": "uint8_t",
    "gcc_va_list": "va_list",
    "_WORD": "unsigned short",
    "_BOOL4": "int",
    "__va_list_tag": "va_list",
    "_IO_FILE": "FILE",
    "DIR": "int",
    "__fsword_t": "long",
    "__kernel_ulong_t": "int",
    "cc_t": "int",
    "speed_t": "int",
    "fd_set": "int",
    "__suseconds_t": "int",
    "_UNKNOWN": "void",
    "__sighandler_t": "void (*)(int)",
    "__compar_fn_t": "int (*)(const void *, const void *)",
}


def normalize_pseudocode_text(text: str) -> str:
    """Apply the text-level portion of the official SK2Decompile normalizer."""
    normalized = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    normalized = re.sub(r"//.*?$", "", normalized, flags=re.MULTILINE)
    normalized = re.sub(
        r"\b(0x[0-9a-fA-F]+)([uUlL]{1,3})?\b",
        lambda match: str(int(match.group(1), 16)) + (match.group(2) or ""),
        normalized,
    )
    normalized = re.sub(
        r"\b(?:__fastcall|__cdecl|__ptr32)\b|\b__noreturn\s+noreturn\b",
        "",
        normalized,
    )
    for alias, replacement in _TYPEDEF_MAP.items():
        normalized = re.sub(rf"\b{re.escape(alias)}\b", replacement, normalized)
    return normalized


def meaningful_body_lines(code: str) -> int:
    body = "{".join(code.split("{")[1:])
    return sum(len(line.strip()) >= 3 for line in body.splitlines())


def rename_generated_target(code: str, target_name: str) -> tuple[str, str | None, int]:
    """Reproduce the official generated-function renaming without touching substrings."""
    prefix, separator, _ = code.partition("(")
    if not separator:
        return code, None, 0
    tokens = prefix.strip().split()
    if not tokens:
        return code, None, 0
    generated_name = tokens[-1].lstrip("*")
    if not re.fullmatch(r"[A-Za-z_]\w*", generated_name):
        return code, None, 0
    if generated_name == target_name:
        return code, generated_name, 0
    renamed, count = re.subn(
        rf"\b{re.escape(generated_name)}\b",
        target_name,
        code,
    )
    return renamed, generated_name, count


class SK2DecompileBackend:
    """Run SK2Decompile structure recovery and identifier recovery sequentially."""

    STRUCT_PREFIX = "# This is the assembly code:\n"
    STRUCT_SUFFIX = "\n# What is the source code?\n"
    IDENT_PREFIX = "# This is the normalized code:\n"
    IDENT_SUFFIX = "\n# What is the source code?\n"

    def __init__(self, config: dict[str, Any], **_: Any):
        self.config = dict(config)
        self.struct_model = self._model_reference(config.get("struct_model_path"), "struct")
        self.ident_model = self._model_reference(config.get("ident_model_path"), "ident")
        self.engine = str(config.get("engine", "vllm")).lower()
        if self.engine not in {"vllm", "transformers"}:
            raise ValueError("engine must be vllm or transformers")
        self.version = str(
            config.get(
                "version",
                f"sk2decompile:{self.struct_model}+{self.ident_model}:{self.engine}",
            )
        )
        self.device = str(config.get("device", "cuda"))
        self.tensor_parallel_size = max(
            1, int(config.get("tensor_parallel_size", config.get("gpus", 1)))
        )
        self.gpu_memory_utilization = float(config.get("gpu_memory_utilization", 0.8))
        self.max_model_len = int(config.get("max_model_len", 32768))
        self.max_new_tokens = int(config.get("max_new_tokens", 4096))
        if self.max_model_len <= self.max_new_tokens:
            raise ValueError("max_model_len must be greater than max_new_tokens")
        self.max_num_seqs = max(1, int(config.get("max_num_seqs", 8)))
        default_batch = self.max_num_seqs if self.engine == "vllm" else 1
        self.stage_batch_size = max(1, int(config.get("stage_batch_size", default_batch)))
        self.temperature = float(config.get("temperature", 0.0))
        self.seed = int(config.get("seed", 0))
        self.use_tqdm = bool(config.get("use_tqdm", False))
        self.preprocess = bool(config.get("preprocess", True))
        self.clang_format = str(config.get("clang_format", "clang-format"))
        self.preprocess_timeout = float(config.get("preprocess_timeout", 2.0))
        self.enforce_official_filter = bool(config.get("enforce_official_filter", False))
        self.rename_target = bool(config.get("rename_target", True))
        self.allowed_languages = {
            str(value).lower() for value in config.get("allowed_languages", ["c"])
        }
        self._prepared: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._active_model: Any = None
        self._active_tokenizer: Any = None
        self._active_sampling_params: Any = None
        self._active_stage: str | None = None

    @staticmethod
    def _model_reference(value: Any, label: str) -> str:
        reference = str(value or "").strip()
        if not reference:
            raise ValueError(f"{label}_model_path is required")
        path = Path(reference).expanduser()
        if path.exists():
            return str(path.resolve())
        if path.is_absolute() or reference.startswith((".", "~")):
            raise ValueError(f"{label}_model_path does not exist: {reference}")
        return reference

    @staticmethod
    def _key(request: DecompileRequest) -> tuple[str, str, str]:
        return request.dataset_id, request.split, request.sample_id

    def _format_pseudocode(self, text: str) -> str:
        normalized = normalize_pseudocode_text(text) if self.preprocess else text
        if not normalized.strip():
            raise ValueError("pseudocode is empty after normalization")
        if self.preprocess:
            result = subprocess.run(
                [self.clang_format, "--style=Google"],
                input=normalized,
                text=True,
                capture_output=True,
                timeout=self.preprocess_timeout,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                detail = (result.stderr or "clang-format returned empty output").strip()
                raise ValueError(f"pseudocode normalization failed: {detail}")
            normalized = "\n".join(
                line for line in result.stdout.splitlines() if line.strip()
            )
        line_count = meaningful_body_lines(normalized)
        if self.enforce_official_filter and not 3 < line_count < 300:
            raise ValueError(
                f"pseudocode rejected by official line filter: {line_count} meaningful body lines"
            )
        return normalized.strip()

    def _activate_model(self, model_reference: str, stage: str) -> None:
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._active_stage = stage
        self._active_tokenizer = AutoTokenizer.from_pretrained(
            model_reference,
            trust_remote_code=False,
        )
        if self._active_tokenizer.pad_token_id is None:
            self._active_tokenizer.pad_token_id = self._active_tokenizer.eos_token_id
        self._active_tokenizer.padding_side = "left"

        if self.engine == "vllm":
            try:
                from vllm import LLM, SamplingParams
            except ImportError as error:
                raise RuntimeError(
                    "vLLM is required for engine=vllm; install with: pip install -e '.[vllm]'"
                ) from error
            self._active_model = LLM(
                model=model_reference,
                tensor_parallel_size=self.tensor_parallel_size,
                max_model_len=self.max_model_len,
                max_num_seqs=self.max_num_seqs,
                gpu_memory_utilization=self.gpu_memory_utilization,
                dtype=self.config.get("dtype", "auto"),
                seed=self.seed,
                trust_remote_code=False,
                **dict(self.config.get("vllm_kwargs", {})),
            )
            stop = self.config.get("stop")
            if stop is None and self._active_tokenizer.eos_token:
                stop = [self._active_tokenizer.eos_token]
            self._active_sampling_params = SamplingParams(
                temperature=self.temperature,
                max_tokens=self.max_new_tokens,
                stop=stop,
                seed=self.seed,
                truncate_prompt_tokens=self.max_model_len - self.max_new_tokens,
            )
            return

        import torch

        if self.device == "cpu":
            dtype = torch.float32
        elif self.device.startswith("cuda") and torch.cuda.is_bf16_supported():
            dtype = torch.bfloat16
        else:
            dtype = torch.float16
        self._active_model = AutoModelForCausalLM.from_pretrained(
            model_reference,
            torch_dtype=dtype,
            trust_remote_code=False,
        ).to(self.device)
        self._active_model.eval()
        self._active_model.config.use_cache = True

    def _generate_active(self, prompts: list[str]) -> list[str]:
        if not prompts:
            return []
        if self._active_model is None or self._active_tokenizer is None:
            raise RuntimeError("SK2Decompile model is not active")
        if self.engine == "vllm":
            outputs = self._active_model.generate(
                prompts,
                self._active_sampling_params,
                use_tqdm=self.use_tqdm,
            )
            if len(outputs) != len(prompts):
                raise ValueError(
                    f"vLLM returned {len(outputs)} outputs for {len(prompts)} prompts"
                )
            return [
                str(output.outputs[0].text if getattr(output, "outputs", None) else "").strip()
                for output in outputs
            ]

        import torch

        inputs = self._active_tokenizer(
            prompts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=self.max_model_len - self.max_new_tokens,
        ).to(self.device)
        input_width = inputs["input_ids"].shape[1]
        with torch.inference_mode():
            generation = {
                "max_new_tokens": self.max_new_tokens,
                "do_sample": self.temperature > 0,
                "pad_token_id": self._active_tokenizer.pad_token_id,
                "eos_token_id": self._active_tokenizer.eos_token_id,
            }
            if self.temperature > 0:
                generation["temperature"] = self.temperature
            outputs = self._active_model.generate(**inputs, **generation)
        return [
            self._active_tokenizer.decode(
                output[input_width:],
                skip_special_tokens=True,
            ).strip()
            for output in outputs
        ]

    def _deactivate_model(self) -> None:
        self._active_sampling_params = None
        self._active_tokenizer = None
        if self._active_model is not None:
            del self._active_model
        self._active_model = None
        gc.collect()
        try:
            import torch

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except ImportError:
            pass
        if self.engine == "vllm":
            try:
                from vllm.distributed.parallel_state import (
                    destroy_distributed_environment,
                    destroy_model_parallel,
                )

                destroy_model_parallel()
                destroy_distributed_environment()
            except (ImportError, RuntimeError, AssertionError):
                pass
        self._active_stage = None

    def _generate_in_chunks(self, prompts: list[str]) -> list[str]:
        results: list[str] = []
        for offset in range(0, len(prompts), self.stage_batch_size):
            results.extend(self._generate_active(prompts[offset : offset + self.stage_batch_size]))
        return results

    def prepare(self, requests: list[DecompileRequest]) -> None:
        self._prepared.clear()
        valid_entries: list[tuple[DecompileRequest, dict[str, Any]]] = []
        for request in requests:
            state: dict[str, Any] = {}
            self._prepared[self._key(request)] = state
            try:
                if request.language.lower() not in self.allowed_languages:
                    raise ValueError(
                        f"language {request.language!r} is unsupported; allowed: "
                        f"{sorted(self.allowed_languages)}"
                    )
                if request.pseudocode is None or not request.pseudocode.text.strip():
                    raise ValueError("pseudocode input is missing")
                normalized = self._format_pseudocode(request.pseudocode.text)
                struct_prompt = self.STRUCT_PREFIX + normalized + self.STRUCT_SUFFIX
                state.update(
                    normalized_pseudocode=normalized,
                    struct_prompt=struct_prompt,
                    pseudocode_view=request.pseudocode.view,
                )
                valid_entries.append((request, state))
            except Exception as error:
                state["error"] = f"{type(error).__name__}: {error}"
                state["reason"] = "sk2_preprocess_failed"

        if not valid_entries:
            return
        self._activate_model(self.struct_model, "struct")
        try:
            try:
                outputs = self._generate_in_chunks(
                    [state["struct_prompt"] for _, state in valid_entries]
                )
                if len(outputs) != len(valid_entries):
                    raise ValueError(
                        f"Structure stage returned {len(outputs)} outputs for "
                        f"{len(valid_entries)} inputs"
                    )
            except Exception as error:
                outputs = [""] * len(valid_entries)
                for _, state in valid_entries:
                    state["reason"] = "sk2_struct_inference_error"
                    state["error"] = f"{type(error).__name__}: {error}"
        finally:
            self._deactivate_model()
        for (_, state), output in zip(valid_entries, outputs):
            state["struct_output"] = output
            if not output and not state.get("reason"):
                state["reason"] = "sk2_empty_struct_output"
                state["error"] = "Structure model returned empty output"

        if any(state.get("struct_output") for _, state in valid_entries):
            self._activate_model(self.ident_model, "ident")

    def _write_artifacts(self, artifact_dir: Path, state: dict[str, Any]) -> None:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        mappings = {
            "sk2_pseudocode_normalized.c": state.get("normalized_pseudocode", ""),
            "sk2_struct_prompt.txt": state.get("struct_prompt", ""),
            "sk2_struct_output.c": state.get("struct_output", ""),
            "sk2_ident_prompt.txt": state.get("ident_prompt", ""),
            "sk2_ident_output.c": state.get("ident_output", ""),
            "sk2_final_output.c": state.get("final_output", ""),
        }
        for name, value in mappings.items():
            if value:
                (artifact_dir / name).write_text(str(value), encoding="utf-8")
        metadata = {
            "engine": self.engine,
            "struct_model": self.struct_model,
            "ident_model": self.ident_model,
            "pseudocode_view": state.get("pseudocode_view"),
            "preprocess": self.preprocess,
            "official_filter_enforced": self.enforce_official_filter,
            "rename_target": self.rename_target,
            "generated_function_name": state.get("generated_function_name"),
            "rename_replacements": state.get("rename_replacements", 0),
            "reason": state.get("reason"),
            "error": state.get("error"),
        }
        (artifact_dir / "sk2_metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def decompile_many(
        self,
        requests: list[DecompileRequest],
        artifact_dirs: list[Path],
    ) -> list[DecompileResult]:
        if len(requests) != len(artifact_dirs):
            raise ValueError("requests and artifact_dirs must have equal length")
        missing = [request for request in requests if self._key(request) not in self._prepared]
        if missing:
            self.prepare(requests)

        started = time.perf_counter()
        ready: list[tuple[int, DecompileRequest, dict[str, Any]]] = []
        results: list[DecompileResult | None] = [None] * len(requests)
        for index, (request, artifact_dir) in enumerate(zip(requests, artifact_dirs)):
            state = self._prepared[self._key(request)]
            if state.get("reason"):
                self._write_artifacts(artifact_dir, state)
                results[index] = DecompileResult(
                    success=False,
                    reason=state["reason"],
                    log=state.get("error", ""),
                    backend_version=self.version,
                )
                continue
            skeleton = str(state.get("struct_output", "")).strip()
            state["ident_prompt"] = self.IDENT_PREFIX + skeleton + self.IDENT_SUFFIX
            ready.append((index, request, state))

        if ready:
            if self._active_stage != "ident":
                self._deactivate_model()
                self._activate_model(self.ident_model, "ident")
            try:
                outputs = self._generate_in_chunks(
                    [state["ident_prompt"] for _, _, state in ready]
                )
            except Exception as error:
                outputs = [""] * len(ready)
                for _, _, state in ready:
                    state["reason"] = "sk2_ident_inference_error"
                    state["error"] = f"{type(error).__name__}: {error}"
            elapsed = (time.perf_counter() - started) / len(ready)
            for (index, request, state), output in zip(ready, outputs):
                state["ident_output"] = output
                final_output = output
                if output and self.rename_target:
                    final_output, old_name, count = rename_generated_target(
                        output,
                        request.function_name,
                    )
                    state["generated_function_name"] = old_name
                    state["rename_replacements"] = count
                state["final_output"] = final_output
                if not output and not state.get("reason"):
                    state["reason"] = "sk2_empty_ident_output"
                    state["error"] = "Identifier model returned empty output"
                self._write_artifacts(artifact_dirs[index], state)
                results[index] = DecompileResult(
                    success=bool(final_output),
                    raw_output=output,
                    code=final_output,
                    reason=state.get("reason"),
                    log=state.get("error", ""),
                    elapsed_seconds=elapsed,
                    backend_version=self.version,
                )

        return [
            result
            if result is not None
            else DecompileResult(
                success=False,
                reason="sk2_internal_error",
                backend_version=self.version,
            )
            for result in results
        ]

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        return self.decompile_many([request], [artifact_dir])[0]

    def close(self) -> None:
        self._deactivate_model()
        self._prepared.clear()
