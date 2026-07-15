from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

from .models import CommandResult


class LocalExecutor:
    def __init__(self, *, require_linux: bool = True, memory_mb: int = 2048, max_file_mb: int = 64):
        self.require_linux = require_linux
        self.memory_mb = memory_mb
        self.max_file_mb = max_file_mb

    def check_environment(self, required: tuple[str, ...] = ("gcc", "g++")) -> None:
        if self.require_linux and platform.system() != "Linux":
            raise RuntimeError("Evaluation must run inside Linux/WSL (set executor.require_linux=false only for tests).")
        missing = [name for name in required if shutil.which(name) is None]
        if missing:
            raise RuntimeError(f"Missing required tools: {', '.join(missing)}")

    def _limits(self):
        if platform.system() != "Linux":
            return None
        memory_bytes = self.memory_mb * 1024 * 1024
        file_bytes = self.max_file_mb * 1024 * 1024

        def apply_limits() -> None:
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        return apply_limits

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        timeout: int,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        started = time.perf_counter()
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=merged_env,
                preexec_fn=self._limits(),
            )
            return CommandResult(
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                elapsed_seconds=time.perf_counter() - started,
            )
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                command=command,
                returncode=-1,
                stdout=(error.stdout or "") if isinstance(error.stdout, str) else "",
                stderr=(error.stderr or "") if isinstance(error.stderr, str) else "",
                elapsed_seconds=time.perf_counter() - started,
                timed_out=True,
            )

