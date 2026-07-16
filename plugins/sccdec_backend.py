"""SCCDec/FAE backend using an OpenAI-compatible inference server.

The SCC stage recompiles the first generated candidate and uses the resulting
assembly/C pair as a self-constructed in-context example for a second pass.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from decomp_eval.models import (
    AssemblyInput,
    CandidateCompileContext,
    DecompileRequest,
    DecompileResult,
)


_FENCE_RE = re.compile(r"```(?:c|cpp|c\+\+)?\s*\n(?P<code>.*?)```", re.DOTALL | re.IGNORECASE)

_ONE_SHOT_PRELUDE = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
"""

_ONE_SHOT_FUNCTION = """bool func0(int num) {
    if (num <= 1) return false;
    for (int i = 2; i * i <= num; i++) {
        if (num % i == 0) return false;
    }
    return true;
}"""


class SCCDecBackend:
    """Run FAE directly, or FAE followed by SCC self-constructed context."""

    version = "sccdec-openai-compatible-v1"

    def __init__(self, config: dict[str, Any]):
        self.config = dict(config)
        self.base_url = str(config.get("base_url", "http://127.0.0.1:8000/v1"))
        self.model = str(config.get("model", "sccdec"))
        self.mode = str(config.get("mode", "scc")).lower()
        if self.mode not in {"fae", "scc"}:
            raise ValueError("mode must be 'fae' or 'scc'")

        self.api_key_env = str(config.get("api_key_env", "SCCDEC_API_KEY"))
        self.api_key = config.get("api_key") or os.environ.get(self.api_key_env) or "not-required"
        self.max_tokens = int(config.get("max_tokens", 1024))
        self.temperature = float(config.get("temperature", 0.0))
        self.timeout = float(config.get("timeout", 300))
        self.compile_timeout = float(config.get("compile_timeout", 30))
        self.max_retries = max(1, int(config.get("max_retries", 3)))
        self.retry_backoff = max(0.0, float(config.get("retry_backoff", 1.0)))
        self.max_concurrency = max(1, int(config.get("max_concurrency", 1)))
        self.objdump = str(config.get("objdump", "objdump"))
        self.recompile_optimization = str(config.get("recompile_optimization", "same"))
        self.one_shot = bool(config.get("one_shot", False))
        self.extra_body = dict(config.get("extra_body", {}))
        self.version = f"{type(self).version}:{self.mode}:{self.model}"
        self._one_shot_assembly: dict[str, str] = {}

        try:
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError(
                "SCCDecBackend requires the OpenAI client; install with: pip install -e '.[api]'"
            ) from error
        self.client = OpenAI(base_url=self.base_url, api_key=str(self.api_key))

    def prepare(self, requests: list[DecompileRequest]) -> None:
        if not self.one_shot:
            return
        for optimization in sorted({request.optimization for request in requests}):
            if optimization in self._one_shot_assembly:
                continue
            fixture = DecompileRequest(
                dataset_id="sccdec",
                split="one_shot",
                sample_id=f"sccdec:one-shot:{optimization}",
                source_group_id="sccdec:one-shot",
                function_name="func0",
                language="c",
                optimization=optimization,
                assembly=AssemblyInput(text="", syntax="att", view="generated"),
                metadata={},
                compile_context=CandidateCompileContext(
                    language="c", compiler="gcc", prelude=_ONE_SHOT_PRELUDE
                ),
            )
            assembly, record = self._build_scc_context(fixture, _ONE_SHOT_FUNCTION)
            if assembly is None:
                raise RuntimeError(
                    f"failed to build SCCDec one-shot context for {optimization}: "
                    f"{record.get('outcome')}"
                )
            self._one_shot_assembly[optimization] = assembly

    @staticmethod
    def _prompt(assembly: str) -> str:
        return (
            "# This is the assembly code:\n"
            f"{assembly.strip()}\n"
            "# What is the source code?"
        )

    @staticmethod
    def _extract_code(text: str) -> tuple[str, str]:
        matches = [match.group("code").strip() for match in _FENCE_RE.finditer(text or "")]
        if matches:
            return matches[-1], "last_c_fence"
        return (text or "").strip(), "raw_text"

    def _infer(self, messages: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
        attempts: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            started = time.perf_counter()
            try:
                parameters: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "timeout": self.timeout,
                }
                if self.extra_body:
                    parameters["extra_body"] = self.extra_body
                response = self.client.chat.completions.create(**parameters)
                content = response.choices[0].message.content or ""
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "success" if content.strip() else "empty_output",
                        "elapsed_seconds": time.perf_counter() - started,
                    }
                )
                if content.strip():
                    return content, {"attempts": attempts, "attempt_count": attempt}
                last_error = RuntimeError("empty model output")
            except Exception as error:  # SDK/provider exceptions vary by implementation.
                last_error = error
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "error",
                        "error_type": type(error).__name__,
                        "error": str(error),
                        "elapsed_seconds": time.perf_counter() - started,
                    }
                )
            if attempt < self.max_retries and self.retry_backoff:
                time.sleep(self.retry_backoff * (2 ** (attempt - 1)))
        raise RuntimeError(f"model inference failed after {self.max_retries} attempts: {last_error}")

    @staticmethod
    def _make_target_external(code: str, function_name: str) -> str:
        match = re.search(rf"\b{re.escape(function_name)}\s*\(", code)
        if not match:
            return code
        prefix = re.sub(
            r"\b(static|inline|__inline|__inline__)\b", "", code[: match.start()]
        )
        return prefix + code[match.start() :]

    @staticmethod
    def _clean_objdump(stdout: str, function_name: str) -> str:
        lines: list[str] = [f"<{function_name}>:"]
        in_function = False
        label_re = re.compile(r"^\s*[0-9a-fA-F]+\s+<([^>]+)>:\s*$")
        instruction_re = re.compile(r"^\s*[0-9a-fA-F]+:\s*(.*)$")
        for line in stdout.splitlines():
            label = label_re.match(line)
            if label:
                symbol = label.group(1)
                if symbol == function_name:
                    in_function = True
                    continue
                if in_function:
                    break
            if not in_function:
                continue
            match = instruction_re.match(line)
            if not match:
                continue
            rest = match.group(1)
            tab_parts = [part.strip() for part in rest.split("\t") if part.strip()]
            instruction = tab_parts[-1] if tab_parts else rest.strip()
            instruction = re.sub(r"^(?:[0-9a-fA-F]{2}\s+)+", "", instruction)
            instruction = instruction.rsplit("#", 1)[0].strip()
            if instruction:
                lines.append(instruction)
        if len(lines) == 1:
            raise RuntimeError(f"objdump did not find instructions for {function_name}")
        return "\n".join(lines)

    def _optimization(self, request: DecompileRequest) -> str:
        value = request.optimization if self.recompile_optimization == "same" else self.recompile_optimization
        value = str(value).lstrip("-")
        if value not in {"O0", "O1", "O2", "O3", "Os", "Oz"}:
            raise ValueError(f"unsupported recompile optimization: {value}")
        return value

    def _build_scc_context(
        self, request: DecompileRequest, candidate: str
    ) -> tuple[str | None, dict[str, Any]]:
        context = request.compile_context
        if context is None:
            return None, {"outcome": "missing_compile_context"}

        suffix = ".c" if context.language.lower() == "c" else ".cpp"
        with tempfile.TemporaryDirectory(prefix="sccdec-") as temporary:
            workdir = Path(temporary)
            source = workdir / f"candidate{suffix}"
            binary = workdir / "candidate.so"
            source.write_text(
                context.prelude
                + "\n"
                + self._make_target_external(candidate, request.function_name)
                + "\n",
                encoding="utf-8",
            )
            command = [
                context.compiler,
                "-shared",
                "-fPIC",
                f"-{self._optimization(request)}",
                *context.flags,
                str(source),
                "-o",
                str(binary),
                *context.libraries,
            ]
            try:
                compile_result = subprocess.run(
                    command,
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    timeout=self.compile_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                return None, {
                    "outcome": "compile_timeout",
                    "command": command,
                    "stdout": error.stdout or "",
                    "stderr": error.stderr or "",
                }
            compile_record = {
                "outcome": "compiled" if compile_result.returncode == 0 else "compile_error",
                "command": command,
                "returncode": compile_result.returncode,
                "stdout": compile_result.stdout,
                "stderr": compile_result.stderr,
            }
            if compile_result.returncode != 0:
                return None, compile_record

            # Use full disassembly instead of --disassemble=<symbol>; older GNU
            # objdump builds do not accept the long-option argument form.
            objdump_command = [self.objdump, "-d", str(binary)]
            try:
                disassembly = subprocess.run(
                    objdump_command,
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    timeout=self.compile_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                return None, {
                    **compile_record,
                    "outcome": "objdump_timeout",
                    "objdump_command": objdump_command,
                    "objdump_stdout": error.stdout or "",
                    "objdump_stderr": error.stderr or "",
                }
            compile_record.update(
                {
                    "objdump_command": objdump_command,
                    "objdump_returncode": disassembly.returncode,
                    "objdump_stderr": disassembly.stderr,
                }
            )
            if disassembly.returncode != 0:
                compile_record["outcome"] = "objdump_error"
                return None, compile_record
            try:
                assembly = self._clean_objdump(disassembly.stdout, request.function_name)
            except Exception as error:
                compile_record.update({"outcome": "assembly_extract_error", "error": str(error)})
                return None, compile_record
            compile_record["outcome"] = "success"
            compile_record["assembly_chars"] = len(assembly)
            return assembly, compile_record

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        metadata: dict[str, Any] = {"mode": self.mode, "model": self.model, "stages": []}

        if request.language.lower() != "c":
            return DecompileResult(
                success=False,
                reason="sccdec_unsupported_language",
                log=f"SCCDec currently supports C only, got {request.language}",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        first_messages: list[dict[str, str]] = []
        if self.one_shot:
            one_shot_assembly = self._one_shot_assembly.get(request.optimization)
            if one_shot_assembly is None:
                return DecompileResult(
                    success=False,
                    reason="sccdec_one_shot_not_prepared",
                    log="prepare() did not build the requested optimization context",
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
            first_messages.extend(
                [
                    {"role": "user", "content": self._prompt(one_shot_assembly)},
                    {"role": "assistant", "content": _ONE_SHOT_FUNCTION},
                ]
            )
        first_messages.append({"role": "user", "content": self._prompt(request.assembly.text)})
        self._write_json(artifact_dir / "sccdec_first_messages.json", first_messages)
        try:
            first_raw, first_inference = self._infer(first_messages)
        except Exception as error:
            metadata.update({"final_stage": "first_inference", "error": repr(error)})
            self._write_json(artifact_dir / "sccdec_metadata.json", metadata)
            return DecompileResult(
                success=False,
                reason="sccdec_first_inference_failed",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        first_code, first_extraction = self._extract_code(first_raw)
        (artifact_dir / "sccdec_first_raw.txt").write_text(first_raw, encoding="utf-8")
        (artifact_dir / "sccdec_first_candidate.c").write_text(first_code + "\n", encoding="utf-8")
        metadata["stages"].append(
            {"name": "first_inference", "extraction": first_extraction, **first_inference}
        )
        if not first_code:
            metadata["final_stage"] = "first_empty_output"
            self._write_json(artifact_dir / "sccdec_metadata.json", metadata)
            return DecompileResult(
                success=False,
                raw_output=first_raw,
                reason="sccdec_empty_output",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        if self.mode == "fae":
            metadata.update({"final_stage": "fae", "scc_applied": False})
            self._write_json(artifact_dir / "sccdec_metadata.json", metadata)
            return DecompileResult(
                success=True,
                raw_output=first_raw,
                code=first_code,
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        context_assembly, compile_record = self._build_scc_context(request, first_code)
        metadata["stages"].append({"name": "self_context_compile", **compile_record})
        if context_assembly is None:
            metadata.update(
                {
                    "final_stage": "first_candidate_fallback",
                    "scc_applied": False,
                    "fallback_reason": compile_record.get("outcome"),
                }
            )
            self._write_json(artifact_dir / "sccdec_metadata.json", metadata)
            return DecompileResult(
                success=True,
                raw_output=first_raw,
                code=first_code,
                log=f"SCC skipped: {compile_record.get('outcome')}",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        (artifact_dir / "sccdec_self_context.s").write_text(context_assembly + "\n", encoding="utf-8")
        second_messages = [
            {"role": "user", "content": self._prompt(context_assembly)},
            {"role": "assistant", "content": first_code},
            {"role": "user", "content": self._prompt(request.assembly.text)},
        ]
        self._write_json(artifact_dir / "sccdec_second_messages.json", second_messages)
        try:
            second_raw, second_inference = self._infer(second_messages)
            second_code, second_extraction = self._extract_code(second_raw)
            metadata["stages"].append(
                {"name": "second_inference", "extraction": second_extraction, **second_inference}
            )
            (artifact_dir / "sccdec_second_raw.txt").write_text(second_raw, encoding="utf-8")
            if not second_code:
                raise RuntimeError("second inference returned empty code")
            (artifact_dir / "sccdec_final_candidate.c").write_text(second_code + "\n", encoding="utf-8")
            metadata.update({"final_stage": "scc", "scc_applied": True})
            self._write_json(artifact_dir / "sccdec_metadata.json", metadata)
            return DecompileResult(
                success=True,
                raw_output=second_raw,
                code=second_code,
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        except Exception as error:
            metadata.update(
                {
                    "final_stage": "first_candidate_fallback",
                    "scc_applied": False,
                    "fallback_reason": "second_inference_failed",
                    "second_inference_error": repr(error),
                }
            )
            self._write_json(artifact_dir / "sccdec_metadata.json", metadata)
            return DecompileResult(
                success=True,
                raw_output=first_raw,
                code=first_code,
                log=f"SCC second pass failed; using first candidate: {error!r}",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

    def decompile_many(self, requests, artifact_dirs):
        if self.max_concurrency == 1 or len(requests) <= 1:
            return [self.decompile(request, path) for request, path in zip(requests, artifact_dirs)]
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as executor:
            futures = [
                executor.submit(self.decompile, request, path)
                for request, path in zip(requests, artifact_dirs)
            ]
            return [future.result() for future in futures]

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if close:
            close()
