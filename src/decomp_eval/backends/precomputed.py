from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .base import BaseBackend
from ..models import DecompileRequest, DecompileResult
from ..util import resolve_path, safe_name


class PrecomputedBackend(BaseBackend):
    def __init__(self, config: dict[str, Any], *, base_dir: Path, **_: Any):
        self.backend_id = config["id"]
        self.version = str(config.get("version", "unknown"))
        self.root = resolve_path(config.get("path", "."), base_dir)
        self.pattern = config.get("pattern", "{sample_id}.c")
        self.mapping: dict[str, dict[str, str]] = {}
        manifest = config.get("manifest")
        if manifest:
            manifest_path = resolve_path(manifest, base_dir)
            with manifest_path.open(encoding="utf-8") as handle:
                for line in handle:
                    row = json.loads(line)
                    self.mapping[str(row["sample_id"])] = {
                        key: str(row[key]) for key in ("code", "path") if row.get(key) is not None
                    }

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        value = self.mapping.get(request.sample_id)
        if value is not None and "code" in value:
            raw = value["code"]
        else:
            relative = (value or {}).get("path") or self.pattern.format(
                sample_id=safe_name(request.sample_id),
                function_name=request.function_name,
                optimization=request.optimization,
                language=request.language,
                split=request.split,
            )
            path = Path(relative)
            path = path if path.is_absolute() else self.root / path
            if not path.exists():
                return DecompileResult(
                    success=False,
                    reason="precomputed_output_missing",
                    log=str(path),
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
            raw = path.read_text(encoding="utf-8", errors="replace")
        return DecompileResult(
            success=bool(raw.strip()),
            raw_output=raw,
            code=raw,
            reason=None if raw.strip() else "decompile_empty_output",
            elapsed_seconds=time.perf_counter() - started,
            backend_version=self.version,
        )
