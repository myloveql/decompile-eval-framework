from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from decomp_eval.models import DecompileRequest, DecompileResult
from plugins.openai_compatible_backend import extract_candidate_code


_SOURCE_FILES = (
    "degpt/__init__.py",
    "degpt/chat.py",
    "degpt/role.py",
    "degpt/util.py",
    "degpt/mssc.py",
    "degpt/prompt.json",
)


def _resolve_root(value: Any) -> Path:
    root = Path(str(value)).expanduser()
    if not root.is_absolute():
        root = (Path.cwd() / root).resolve()
    else:
        root = root.resolve()
    if not (root / "degpt" / "role.py").is_file():
        raise ValueError(f"DeGPT root does not contain degpt/role.py: {root}")
    return root


def _source_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in _SOURCE_FILES:
        path = root / relative
        if not path.is_file():
            raise ValueError(f"DeGPT source file is missing: {path}")
        digest.update(relative.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _api_key(config: dict[str, Any]) -> str:
    if config.get("api_key"):
        return str(config["api_key"])
    env_name = str(config.get("api_key_env", "DEGPT_API_KEY"))
    return os.environ.get(env_name, "")


class DeGPTBackend:
    """Run the upstream DeGPT role-based pseudocode optimizer."""

    version = "degpt-adapter-v1"

    def __init__(self, config: dict[str, Any], **_: Any):
        self.config = dict(config)
        self.root = _resolve_root(config.get("degpt_root", "../DeGPT"))
        self.model = str(config.get("model", "gpt-3.5-turbo"))
        self.base_url = str(config.get("base_url", "https://api.openai.com/v1/"))
        self.api_key = _api_key(config)
        self.temperature = float(config.get("temperature", 0.2))
        self.api_key_env = str(config.get("api_key_env", "DEGPT_API_KEY"))
        self._role_module: Any = None
        self.version = (
            f"{type(self).version}:{_source_fingerprint(self.root)}:"
            f"{self.model}:{self.temperature:g}"
        )

    def _load_role(self) -> Any:
        if self._role_module is not None:
            return self._role_module
        root_text = str(self.root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)
        try:
            self._role_module = importlib.import_module("degpt.role")
        except ImportError as error:
            raise RuntimeError(
                "DeGPT dependencies are unavailable; install with: "
                "pip install -e '.[degpt]'"
            ) from error
        return self._role_module

    def prepare(self, requests: list[DecompileRequest]) -> None:
        # The upstream client reads these values from config.ini. Environment
        # overrides keep the repository config unchanged and avoid concurrent
        # workers rewriting a shared file.
        os.environ["DEGPT_MODEL"] = self.model
        os.environ["DEGPT_API_BASE"] = self.base_url
        os.environ["DEGPT_API_KEY"] = self.api_key
        os.environ["DEGPT_TEMPERATURE"] = str(self.temperature)
        os.environ["DEGPT_DISABLE_ATEXIT_LOG"] = "1"
        self._load_role()

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        metadata: dict[str, Any] = {
            "implementation": "degpt_adapter",
            "model": self.model,
            "base_url": self.base_url,
            "temperature": self.temperature,
            "backend_version": self.version,
        }

        if request.pseudocode is None or not request.pseudocode.text.strip():
            return DecompileResult(
                success=False,
                reason="degpt_missing_pseudocode",
                log="DeGPT requires pseudocode input",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        code = request.pseudocode.text.strip()
        (artifact_dir / "degpt_input.c").write_text(code + "\n", encoding="utf-8")
        try:
            role = self._load_role()
            result = role.RoleModel(decompile_code=code).work(end_at="DONE")
            candidate = str(result.get("output", "")).strip()
            metadata.update(
                {
                    "workflow": result.get("workflow"),
                    "sorted_directions": [str(item) for item in result.get("sorted_directions", [])],
                    "original_directions": [str(item) for item in result.get("original_directions", [])],
                    "optimization": result.get("optimization", {}),
                }
            )
            (artifact_dir / "degpt_result.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
            (artifact_dir / "degpt_final.c").write_text(
                candidate + ("\n" if candidate else ""), encoding="utf-8"
            )
        except Exception as error:
            metadata.update({"error_type": type(error).__name__, "error": repr(error)})
            (artifact_dir / "degpt_metadata.json").write_text(
                json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            return DecompileResult(
                success=False,
                reason="degpt_pipeline_failed",
                log=repr(error),
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

        metadata["candidate_empty"] = not bool(candidate)
        (artifact_dir / "degpt_metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        if not candidate:
            return DecompileResult(
                success=False,
                reason="degpt_empty_output",
                log="DeGPT returned no optimized code",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        return DecompileResult(
            success=True,
            raw_output=candidate,
            code=extract_candidate_code(candidate)[0],
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )

    def close(self) -> None:
        self._role_module = None
