from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from .base import BaseBackend
from ..models import DecompileRequest, DecompileResult, ensure_artifact_dir


class CommandBackend(BaseBackend):
    """Run one external command per sample.

    Supported placeholders: assembly_file, output_file, request_file, sample_id,
    function_name, optimization, language and artifact_dir.
    """

    def __init__(self, config: dict[str, Any], **_: Any):
        self.backend_id = config["id"]
        self.version = str(config.get("version", "unknown"))
        self.command = config.get("command")
        if not self.command:
            raise ValueError(f"command backend {self.backend_id} requires command")
        self.timeout = int(config.get("timeout", 300))
        self.env = {str(k): str(v) for k, v in config.get("env", {}).items()}
        self.output_mode = config.get("output_mode", "file")

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        ensure_artifact_dir(artifact_dir)
        assembly_file = artifact_dir / "assembly.s"
        output_file = artifact_dir / "backend_output.c"
        request_file = artifact_dir / "request.json"
        assembly_file.write_text(request.assembly.text, encoding="utf-8")
        import json

        request_file.write_text(json.dumps(request.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        values = {
            "assembly_file": str(assembly_file),
            "output_file": str(output_file),
            "request_file": str(request_file),
            "sample_id": request.sample_id,
            "function_name": request.function_name,
            "optimization": request.optimization,
            "language": request.language,
            "artifact_dir": str(artifact_dir),
        }
        tokens = shlex.split(self.command) if isinstance(self.command, str) else list(self.command)
        command = [str(token).format_map(values) for token in tokens]
        env = os.environ.copy()
        env.update(self.env)
        try:
            result = subprocess.run(
                command,
                cwd=artifact_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as error:
            return DecompileResult(
                success=False,
                reason="decompile_timeout",
                log=str(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        if result.returncode != 0:
            return DecompileResult(
                success=False,
                reason="decompile_command_error",
                log=(result.stdout + "\n" + result.stderr)[-8000:],
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        if self.output_mode == "stdout":
            raw = result.stdout
        elif output_file.exists():
            raw = output_file.read_text(encoding="utf-8", errors="replace")
        else:
            return DecompileResult(
                success=False,
                reason="decompile_output_missing",
                log=result.stderr[-8000:],
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        return DecompileResult(
            success=bool(raw.strip()),
            raw_output=raw,
            code=raw,
            reason=None if raw.strip() else "decompile_empty_output",
            log=result.stderr[-8000:],
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )

