from __future__ import annotations

from pathlib import Path

from ..models import CanonicalSample, DecompileRequest, DecompileResult


class BaseBackend:
    backend_id = "base"
    version = "unknown"

    def prepare(self, samples: list[CanonicalSample]) -> None:
        return None

    def decompile_many(
        self, requests: list[DecompileRequest], artifact_dirs: list[Path]
    ) -> list[DecompileResult]:
        return [self.decompile(request, path) for request, path in zip(requests, artifact_dirs)]

    def close(self) -> None:
        return None

