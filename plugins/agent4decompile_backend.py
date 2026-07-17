from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from decomp_eval.models import DecompileRequest, DecompileResult


_OPT_RE = re.compile(r"^-O(?:0|1|2|3|s|z|fast)$", re.IGNORECASE)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _resolve_root(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve()


def _agent4_source_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((root / "src").rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _import_agent4(root: Path) -> tuple[type, type, Callable[[str, str], str]]:
    """Import Agent4Decompile without copying any of its prompts into this plugin."""
    if not root.is_dir():
        raise ValueError(f"Agent4Decompile root does not exist: {root}")
    if not (root / "src" / "refinement" / "refiner.py").is_file():
        raise ValueError(
            f"Agent4Decompile refiner was not found under {root / 'src/refinement/refiner.py'}"
        )

    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    refiner_module = importlib.import_module("src.refinement.refiner")
    module_path = Path(refiner_module.__file__).resolve()
    if not module_path.is_relative_to(root):
        raise RuntimeError(
            "Python already imported a different top-level 'src' package; "
            f"expected Agent4Decompile under {root}, got {module_path}"
        )
    pipeline_module = importlib.import_module("src.pipeline")
    return (
        refiner_module.MCGDRefiner,
        pipeline_module.Agent4DecompilePipeline,
        refiner_module.preprocess_decompiled_code,
    )


class FrameworkConstraintEvaluator:
    """Test-free L1/L2 feedback for a dataset target-function translation unit."""

    def __init__(
        self,
        request: DecompileRequest,
        artifact_dir: Path,
        *,
        timeout: float,
        optimization: str,
    ):
        if request.compile_context is None:
            raise ValueError("Agent4Decompile L1/L2 requires compile_context")
        self.request = request
        self.context = request.compile_context
        self.artifact_dir = artifact_dir
        self.timeout = timeout
        self.optimization = self._optimization(optimization)
        self.records: list[dict[str, Any]] = []
        self._evaluation_index = 0

    def _optimization(self, configured: str) -> str:
        value = self.request.optimization if configured == "same" else configured
        value = str(value).lstrip("-")
        if value.lower() not in {"o0", "o1", "o2", "o3", "os", "oz", "ofast"}:
            raise ValueError(f"unsupported Agent4Decompile optimization: {value}")
        return f"-{value}"

    def _source(self, code: str) -> str:
        prelude = self.context.prelude.rstrip()
        return f"{prelude}\n{code.strip()}\n" if prelude else f"{code.strip()}\n"

    def _flags(self) -> list[str]:
        return [flag for flag in self.context.flags if not _OPT_RE.match(str(flag))]

    def _run(self, stage: str, code: str, command: list[str]) -> tuple[bool, str, dict[str, Any]]:
        index = self._evaluation_index
        source_path = self.artifact_dir / f"constraint_{index:02d}_{stage}.c"
        source_path.write_text(self._source(code), encoding="utf-8")
        resolved = [str(source_path) if item == "{source}" else item for item in command]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                resolved,
                cwd=self.artifact_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            record = {
                "stage": stage,
                "command": resolved,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "elapsed_seconds": time.perf_counter() - started,
                "timed_out": False,
            }
            return completed.returncode == 0, completed.stderr, record
        except subprocess.TimeoutExpired as error:
            record = {
                "stage": stage,
                "command": resolved,
                "returncode": None,
                "stdout": error.stdout or "",
                "stderr": error.stderr or "",
                "elapsed_seconds": time.perf_counter() - started,
                "timed_out": True,
            }
            return False, f"timeout after {self.timeout:g}s", record

    def evaluate_all(
        self,
        code: str,
        original_binary: str | None = None,
        test_cases: list[dict[str, Any]] | None = None,
        constraint_level: int = 2,
        exebench_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # These assertions make accidental benchmark-oracle leakage fail closed.
        if test_cases is not None or exebench_data is not None:
            raise ValueError("fair Agent4Decompile mode must not receive evaluation test data")
        if constraint_level not in {1, 2}:
            raise ValueError("fair Agent4Decompile backend only supports constraint_level 1 or 2")

        compiler = self.context.compiler
        flags = self._flags()
        syntax_command = [compiler, *flags, self.optimization, "-fsyntax-only", "{source}"]
        syntax_ok, syntax_error, syntax_record = self._run("syntax", code, syntax_command)
        records = [syntax_record]
        if syntax_ok:
            syntax_message = "✓ Valid C syntax"
        else:
            syntax_message = f"✗ Syntax errors:\n{syntax_error[:2000]}"

        compile_ok = False
        if syntax_ok and constraint_level >= 2:
            object_path = self.artifact_dir / f"constraint_{self._evaluation_index:02d}.o"
            compile_command = [
                compiler,
                *flags,
                self.optimization,
                "-c",
                "{source}",
                "-o",
                str(object_path),
            ]
            compile_ok, compile_error, compile_record = self._run(
                "compilation", code, compile_command
            )
            records.append(compile_record)
            compile_message = (
                "✓ Compiles successfully"
                if compile_ok
                else f"✗ Compilation errors:\n{compile_error[:2000]}"
            )
        elif constraint_level == 1:
            compile_message = "Skipped at constraint level 1"
        else:
            compile_message = "Fix syntax first"

        entry = {
            "evaluation": self._evaluation_index,
            "syntax_pass": syntax_ok,
            "compilation_pass": compile_ok,
            "commands": records,
        }
        self.records.append(entry)
        _write_json(
            self.artifact_dir / f"constraint_{self._evaluation_index:02d}.json", entry
        )
        self._evaluation_index += 1
        return {
            "syntax": {"pass": syntax_ok, "message": syntax_message},
            "compilation": {"pass": compile_ok, "message": compile_message},
            "execution": {"pass": None, "message": "No evaluation oracle provided", "details": {}},
        }


class Agent4DecompileBackend:
    """Adapt Agent4Decompile while keeping its original prompt implementation authoritative."""

    version = "agent4decompile-adapter-v1"

    def __init__(self, config: dict[str, Any]):
        self.config = copy.deepcopy(config)
        if "agent4_root" not in config:
            raise ValueError("plugin_config.agent4_root is required")
        self.agent4_root = _resolve_root(config["agent4_root"])
        self.mode = str(config.get("mode", "pseudocode_refine")).lower()
        if self.mode not in {"pseudocode_refine", "binary_single", "binary_consensus"}:
            raise ValueError(
                "mode must be pseudocode_refine, binary_single, or binary_consensus"
            )
        self.constraint_level = int(config.get("constraint_level", 2))
        if self.constraint_level not in {1, 2}:
            raise ValueError(
                "constraint_level must be 1 or 2; benchmark-test L3 is intentionally unavailable"
            )
        self.max_iterations = max(1, int(config.get("max_iterations", 5)))
        self.architecture = str(config.get("architecture", "x86_64"))
        self.allowed_languages = {
            str(value).lower() for value in config.get("allowed_languages", ["c"])
        }
        self.compile_timeout = float(config.get("compile_timeout", 60))
        self.compile_optimization = str(config.get("compile_optimization", "same"))
        self.traditional_decompiler = str(config.get("traditional_decompiler", "ghidra"))
        self.ghidra_path = config.get("ghidra_path")
        self.retdec_path = config.get("retdec_path")

        llm = dict(config.get("llm", {}))
        self.llm_provider = str(llm.get("provider", "openai_compatible")).lower()
        self.model = llm.get("model")
        self.base_url = llm.get("base_url")
        self.api_key_env = str(llm.get("api_key_env", "OPENAI_API_KEY"))
        self.api_key = llm.get("api_key") or os.environ.get(self.api_key_env)
        self.temperature = float(llm.get("temperature", 0.2))
        self.max_tokens = int(llm.get("max_tokens", 8000))
        self.request_timeout = float(llm.get("timeout", 300))
        self.max_retries = max(1, int(llm.get("max_retries", 3)))
        self.retry_backoff = max(0.0, float(llm.get("retry_backoff", 1)))
        self.thinking_mode = str(llm.get("thinking_mode", "auto")).lower()
        self.thinking_protocol = str(llm.get("thinking_protocol", "auto")).lower()
        self.extra_body = self._thinking_body(dict(llm.get("extra_body", {})))

        self.refiner_class, self.pipeline_class, self.preprocess = _import_agent4(
            self.agent4_root
        )
        self.agent4_source_sha256 = _agent4_source_hash(self.agent4_root)
        self.prompt_source = str(
            Path(importlib.import_module(self.refiner_class.__module__).__file__).resolve()
        )
        self.version = (
            f"{type(self).version}:{self.mode}:{self.llm_provider}:{self.model or 'default'}:"
            f"L{self.constraint_level}:i{self.max_iterations}:"
            f"src-{self.agent4_source_sha256[:12]}"
        )
        self._client = None
        if self.llm_provider == "openai_compatible":
            if not self.model:
                raise ValueError("plugin_config.llm.model is required for openai_compatible")
            if not self.api_key:
                raise ValueError(
                    f"API key is not set; configure llm.api_key or environment {self.api_key_env}"
                )
            try:
                from openai import OpenAI
            except ImportError as error:
                raise RuntimeError("Agent4Decompile API mode requires: pip install -e '.[api]'") from error
            parameters: dict[str, Any] = {"api_key": str(self.api_key)}
            if self.base_url:
                parameters["base_url"] = str(self.base_url)
            self._client = OpenAI(**parameters)
        elif self.llm_provider not in {"deepseek", "openai", "anthropic"}:
            raise ValueError(
                "llm.provider must be openai_compatible, deepseek, openai, or anthropic"
            )

    def _thinking_body(self, configured: dict[str, Any]) -> dict[str, Any]:
        if self.thinking_mode not in {"auto", "enabled", "disabled"}:
            raise ValueError("thinking_mode must be auto, enabled, or disabled")
        if self.thinking_mode == "auto":
            return configured
        protocol = self.thinking_protocol
        if protocol == "auto":
            protocol = "thinking_type" if "kimi" in str(self.model).lower() else "enable_thinking"
        if protocol == "thinking_type":
            payload = {"thinking": {"type": self.thinking_mode}}
        elif protocol == "enable_thinking":
            payload = {"enable_thinking": self.thinking_mode == "enabled"}
        elif protocol == "custom":
            payload = {}
        else:
            raise ValueError(
                "thinking_protocol must be auto, thinking_type, enable_thinking, or custom"
            )
        overlap = set(configured) & set(payload)
        if overlap:
            raise ValueError(f"thinking configuration conflicts with extra_body: {sorted(overlap)}")
        return {**configured, **payload}

    def prepare(self, requests: list[DecompileRequest]) -> None:
        for request in requests:
            if request.language.lower() not in self.allowed_languages:
                continue
            if request.compile_context and shutil.which(request.compile_context.compiler) is None:
                raise RuntimeError(
                    f"Agent4Decompile compiler not found: {request.compile_context.compiler}"
                )

    def _api_call(self, system_prompt: str, prompt: str) -> str:
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                parameters: dict[str, Any] = {
                    "model": self.model,
                    # These two messages exactly match Agent4Decompile's original _call_llm.
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "timeout": self.request_timeout,
                }
                if self.extra_body:
                    parameters["extra_body"] = self.extra_body
                response = self._client.chat.completions.create(**parameters)
                content = response.choices[0].message.content or ""
                if content.strip():
                    return content
                last_error = RuntimeError("empty model output")
            except Exception as error:  # Provider SDK exception classes vary.
                last_error = error
            if attempt < self.max_retries and self.retry_backoff:
                time.sleep(self.retry_backoff * (2 ** (attempt - 1)))
        raise RuntimeError(
            f"Agent4Decompile model inference failed after {self.max_retries} attempts: {last_error}"
        )

    def _initial_code(self, request: DecompileRequest, artifact_dir: Path) -> tuple[str, str]:
        if self.mode == "pseudocode_refine":
            if request.pseudocode is None or not request.pseudocode.text.strip():
                raise ValueError("pseudocode_refine requires a non-empty pseudocode input")
            return request.pseudocode.text, request.pseudocode.producer

        if request.binary is None or not request.binary.path:
            raise ValueError(f"{self.mode} requires a binary input")
        pipeline = self.pipeline_class(
            decompiler=self.traditional_decompiler,
            llm_provider="deepseek",
            max_iterations=self.max_iterations,
            constraint_level=self.constraint_level,
            multi_decompiler=self.mode == "binary_consensus",
            ghidra_path=self.ghidra_path,
            retdec_path=self.retdec_path,
            architecture=request.binary.architecture or self.architecture,
        )
        result = pipeline.run(
            request.binary.path,
            output_dir=str(artifact_dir / "traditional"),
            skip_refinement=True,
        )
        if not result.success or not result.refined_code:
            raise RuntimeError(result.error_message or "Agent4Decompile traditional stage failed")
        producer = "consensus" if self.mode == "binary_consensus" else self.traditional_decompiler
        return result.refined_code, producer

    def _new_refiner(self, evaluator: FrameworkConstraintEvaluator):
        if self.llm_provider == "openai_compatible":
            refiner = self.refiner_class.__new__(self.refiner_class)
            refiner.llm_provider = "openai"
            refiner.max_iterations = self.max_iterations
            refiner.constraint_level = self.constraint_level
            refiner.architecture = self.architecture
            refiner.evaluator = evaluator
            refiner.model = self.model
            return refiner, None
        refiner = self.refiner_class(
            llm_provider=self.llm_provider,
            model=self.model,
            max_iterations=self.max_iterations,
            constraint_level=self.constraint_level,
            architecture=self.architecture,
        )
        refiner.evaluator = evaluator
        return refiner, refiner._call_llm

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        metadata: dict[str, Any] = {
            "mode": self.mode,
            "constraint_level": self.constraint_level,
            "max_iterations": self.max_iterations,
            "prompt_source": self.prompt_source,
            "agent4_source_sha256": self.agent4_source_sha256,
            "prompt_policy": "runtime_import_from_agent4decompile",
            "oracle_assisted": False,
            "request_has_private_tests": False,
        }
        if request.language.lower() not in self.allowed_languages:
            return DecompileResult(
                success=False,
                reason="agent4decompile_unsupported_language",
                log=f"Agent4Decompile supports {sorted(self.allowed_languages)}, got {request.language}",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        if request.compile_context is None:
            return DecompileResult(
                success=False,
                reason="agent4decompile_missing_compile_context",
                log="required_inputs must include compile_context",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        try:
            initial_code, producer = self._initial_code(request, artifact_dir)
            (artifact_dir / "agent4_initial.c").write_text(initial_code, encoding="utf-8")
            preprocessed = self.preprocess(initial_code, producer)
            (artifact_dir / "agent4_preprocessed.c").write_text(preprocessed, encoding="utf-8")
            evaluator = FrameworkConstraintEvaluator(
                request,
                artifact_dir,
                timeout=self.compile_timeout,
                optimization=self.compile_optimization,
            )
            refiner, native_call = self._new_refiner(evaluator)
            system_prompt = refiner.SYSTEM_PROMPT
            (artifact_dir / "agent4_system_prompt.txt").write_text(
                system_prompt, encoding="utf-8"
            )
            trace_index = 0

            def traced_call(prompt: str) -> str:
                nonlocal trace_index
                (artifact_dir / f"iteration_{trace_index:02d}_prompt.txt").write_text(
                    prompt, encoding="utf-8"
                )
                response = (
                    self._api_call(system_prompt, prompt)
                    if native_call is None
                    else native_call(prompt)
                )
                (artifact_dir / f"iteration_{trace_index:02d}_response.txt").write_text(
                    response or "", encoding="utf-8"
                )
                candidate = refiner._extract_code(response or "")
                (artifact_dir / f"iteration_{trace_index:02d}_candidate.c").write_text(
                    candidate, encoding="utf-8"
                )
                trace_index += 1
                return response

            refiner._call_llm = traced_call
            try:
                refinement = refiner.refine(
                    initial_code=initial_code,
                    binary_name=request.function_name,
                    decompiler=producer,
                    original_binary_path=None,
                    test_cases=None,
                    exebench_data=None,
                )
            finally:
                native_client = getattr(refiner, "_client", None)
                close_native = getattr(native_client, "close", None)
                if close_native:
                    close_native()
            final_code = refinement.refined_code or ""
            (artifact_dir / "agent4_final_candidate.c").write_text(
                final_code, encoding="utf-8"
            )
            metadata.update(
                {
                    "producer": producer,
                    "iterations": refinement.iterations,
                    "syntax_valid": refinement.syntax_valid,
                    "compiles": refinement.compiles,
                    "re_executable": refinement.re_executable,
                    "internal_success": refinement.success,
                    "internal_error": refinement.error_message,
                    "iteration_history": refinement.iteration_history,
                    "constraint_records": evaluator.records,
                    "llm_calls": trace_index,
                }
            )
            _write_json(artifact_dir / "agent4_metadata.json", metadata)
            if not final_code.strip():
                return DecompileResult(
                    success=False,
                    reason="agent4decompile_empty_output",
                    log=refinement.error_message or "Agent4Decompile returned empty code",
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
            # Generation succeeded if a candidate exists. Official compilation and behavior
            # are deliberately determined later by the dataset-bound evaluation protocol.
            return DecompileResult(
                success=True,
                raw_output=final_code,
                code=final_code,
                log=refinement.error_message or "",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        except Exception as error:
            metadata.update({"error_type": type(error).__name__, "error": repr(error)})
            _write_json(artifact_dir / "agent4_metadata.json", metadata)
            return DecompileResult(
                success=False,
                reason="agent4decompile_failed",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

    def close(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if close:
                close()
