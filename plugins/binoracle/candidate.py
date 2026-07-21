from __future__ import annotations

import hashlib
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .security import inspect_candidate_source, sanitized_subprocess_environment


GHIDRA_COMPAT_PRELUDE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
""".strip()


def externalize_candidate(code: str, function_name: str) -> str:
    match = re.search(rf"\b{re.escape(function_name)}\s*\(", code)
    if not match:
        return code
    prefix = re.sub(
        r"\b(static|inline|__inline|__inline__|extern)\b", "", code[: match.start()]
    )
    return prefix + code[match.start() :]


@dataclass(frozen=True)
class CandidateBuild:
    success: bool
    source: Path
    object: Path
    manifest: dict[str, Any]


class CandidateCompiler:
    version = "binoracle-candidate-compiler-v2"

    def __init__(self, config: dict[str, Any]):
        self.compiler = str(config.get("candidate_compiler", "gcc"))
        self.timeout = float(config.get("candidate_compile_timeout", 120))
        self.prelude = str(config.get("candidate_public_prelude", GHIDRA_COMPAT_PRELUDE))
        self.compile_gate_enabled = bool(config.get("candidate_compile_gate_enabled", False))
        raw_gate_prelude = config.get("candidate_compile_gate_prelude")
        if self.compile_gate_enabled:
            if not isinstance(raw_gate_prelude, str) or not raw_gate_prelude.strip():
                raise ValueError(
                    "candidate_compile_gate_prelude must contain public wrapper declarations "
                    "when candidate_compile_gate_enabled is true"
                )
            self.compile_gate_prelude = raw_gate_prelude
        else:
            self.compile_gate_prelude = ""

    def _compile(
        self,
        *,
        code: str,
        function_name: str,
        optimization: str,
        stage_dir: Path,
        source_name: str,
        object_name: str,
        prelude: str,
        gate: bool,
    ) -> CandidateBuild:
        stage_dir.mkdir(parents=True, exist_ok=True)
        source = stage_dir / source_name
        object_path = stage_dir / object_name
        security = inspect_candidate_source(code)
        source.write_text(
            prelude + "\n\n" + externalize_candidate(code.strip(), function_name) + "\n",
            encoding="utf-8",
        )
        gate_metadata = {
            "enabled": gate,
            "public_declarations_sha256": hashlib.sha256(
                self.compile_gate_prelude.encode("utf-8")
            ).hexdigest()
            if gate
            else None,
        }
        if not security.allowed:
            manifest = {
                "schema_version": 1,
                "compiler_version": self.version,
                "command": [],
                "returncode": None,
                "stdout": "",
                "stderr": "candidate rejected by security policy: " + ", ".join(security.reasons),
                "timed_out": False,
                "success": False,
                "elapsed_seconds": 0.0,
                "uses_private_compile_context": False,
                "security_policy": security.to_dict(),
                "compile_gate": gate_metadata,
            }
            return CandidateBuild(False, source, object_path, manifest)
        normalized_optimization = optimization.upper()
        if normalized_optimization not in {"O0", "O1", "O2", "O3", "OS", "OG"}:
            normalized_optimization = "O0"
        command = [
            self.compiler,
            "-c",
            f"-{normalized_optimization}",
            "-std=gnu11",
            "-fcommon",
            "-fno-pie",
            "-w",
            "-o",
            str(object_path),
            str(source),
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=stage_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                env=sanitized_subprocess_environment(),
            )
            timed_out = False
            returncode = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as error:
            timed_out = True
            returncode = None
            stdout = error.stdout or ""
            stderr = error.stderr or ""
        success = not timed_out and returncode == 0 and object_path.is_file()
        manifest = {
            "schema_version": 1,
            "compiler_version": self.version,
            "command": command,
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "success": success,
            "elapsed_seconds": time.perf_counter() - started,
            "uses_private_compile_context": False,
            "security_policy": security.to_dict(),
            "compile_gate": gate_metadata,
        }
        return CandidateBuild(success, source, object_path, manifest)

    def compile(
        self,
        *,
        code: str,
        function_name: str,
        optimization: str,
        stage_dir: Path,
    ) -> CandidateBuild:
        return self._compile(
            code=code,
            function_name=function_name,
            optimization=optimization,
            stage_dir=stage_dir,
            source_name="candidate.c",
            object_name="candidate.o",
            prelude=self.prelude,
            gate=False,
        )

    def compile_gate(
        self,
        *,
        code: str,
        function_name: str,
        optimization: str,
        stage_dir: Path,
    ) -> CandidateBuild | None:
        """Compile only against independently supplied public wrapper declarations."""
        if not self.compile_gate_enabled:
            return None
        return self._compile(
            code=code,
            function_name=function_name,
            optimization=optimization,
            stage_dir=stage_dir,
            source_name="candidate_compile_gate.c",
            object_name="candidate_compile_gate.o",
            prelude=self.prelude + "\n\n" + self.compile_gate_prelude,
            gate=True,
        )
