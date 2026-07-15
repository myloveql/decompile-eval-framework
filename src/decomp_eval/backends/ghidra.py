from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..models import DecompileRequest, DecompileResult, ensure_artifact_dir
from ..util import resolve_path
from .base import BaseBackend


class GhidraHeadlessBackend(BaseBackend):
    """Decompile one named function from an existing binary with Ghidra Headless."""

    required_inputs = ("binary",)

    def __init__(self, config: dict[str, Any], *, base_dir: Path):
        self.backend_id = config["id"]
        self.ghidra_root = resolve_path(config["ghidra_path"], base_dir)
        self.analyze_headless = self._find_analyze_headless(self.ghidra_root)
        default_script = Path(__file__).with_name("ghidra_scripts") / "DecompileFunction.java"
        self.script = resolve_path(config.get("script_path", default_script), base_dir)
        self.timeout = int(config.get("timeout", 300))
        self.analysis_timeout = int(config.get("analysis_timeout", 120))
        self.verify_binary_hash = bool(config.get("verify_binary_hash", True))
        self.version = str(config.get("version") or self._read_version() or "unknown")

    @staticmethod
    def _find_analyze_headless(path: Path) -> Path:
        if path.is_file():
            return path
        names = ["analyzeHeadless.bat", "analyzeHeadless"] if os.name == "nt" else [
            "analyzeHeadless", "analyzeHeadless.bat"
        ]
        candidates = [path / "support" / name for name in names]
        return next((candidate for candidate in candidates if candidate.exists()), candidates[0])

    def _read_version(self) -> str | None:
        properties = self.ghidra_root / "Ghidra" / "application.properties"
        if not properties.exists():
            return None
        match = re.search(
            r"^application\.version\s*=\s*(.+?)\s*$",
            properties.read_text(encoding="utf-8", errors="replace"),
            flags=re.MULTILINE,
        )
        return match.group(1) if match else None

    def prepare(self, samples) -> None:
        if not self.analyze_headless.is_file():
            raise FileNotFoundError(f"Ghidra analyzeHeadless not found: {self.analyze_headless}")
        if not self.script.is_file():
            raise FileNotFoundError(f"Ghidra post-script not found: {self.script}")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir = ensure_artifact_dir(artifact_dir).resolve()
        if request.binary is None or not request.binary.path:
            return self._failure("binary_missing", started)
        source_binary = Path(request.binary.path)
        if not source_binary.is_file():
            return self._failure("binary_not_found", started, str(source_binary))
        if (
            self.verify_binary_hash
            and request.binary.sha256
            and self._sha256(source_binary).lower() != request.binary.sha256.lower()
        ):
            return self._failure("binary_hash_mismatch", started, str(source_binary))

        binary = artifact_dir / ("input_binary" + source_binary.suffix)
        shutil.copy2(source_binary, binary)
        output_file = artifact_dir / "backend_output.c"
        project_dir = artifact_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        command = [
            str(self.analyze_headless),
            str(project_dir),
            "decompile_project",
            "-import",
            str(binary),
            "-analysisTimeoutPerFile",
            str(self.analysis_timeout),
            "-scriptPath",
            str(self.script.parent),
            "-postScript",
            self.script.name,
            str(output_file),
            request.function_name,
            str(self.analysis_timeout),
            "-deleteProject",
        ]
        if os.name == "nt" and self.analyze_headless.suffix.lower() in {".bat", ".cmd"}:
            command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", *command]
        try:
            completed = subprocess.run(
                command,
                cwd=artifact_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as error:
            return self._failure("decompile_timeout", started, str(error))
        (artifact_dir / "ghidra.stdout.log").write_text(completed.stdout, encoding="utf-8")
        (artifact_dir / "ghidra.stderr.log").write_text(completed.stderr, encoding="utf-8")
        log = (completed.stdout + "\n" + completed.stderr)[-16000:]
        if completed.returncode != 0:
            return self._failure("ghidra_headless_error", started, log)
        if not output_file.is_file():
            return self._failure("decompile_output_missing", started, log)
        raw = output_file.read_text(encoding="utf-8", errors="replace")
        if not raw.strip():
            return self._failure("decompile_empty_output", started, log)
        return DecompileResult(
            success=True,
            raw_output=raw,
            code=raw,
            log=log,
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )

    def _failure(self, reason: str, started: float, log: str = "") -> DecompileResult:
        return DecompileResult(
            success=False,
            reason=reason,
            log=log,
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )
