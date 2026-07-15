from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import BaseBackend
from ..models import CanonicalSample, DecompileRequest, DecompileResult
from ..util import load_object


class PythonPluginBackend(BaseBackend):
    def __init__(self, config: dict[str, Any], **_: Any):
        self.backend_id = config["id"]
        self.required_inputs = tuple(config.get("required_inputs", ("assembly",)))
        self.version = str(config.get("version", "unknown"))
        factory = load_object(config["plugin"])
        plugin_config = config.get("plugin_config", {})
        self.plugin = factory(plugin_config) if isinstance(factory, type) else factory
        self.version = str(getattr(self.plugin, "version", self.version))

    def prepare(self, samples: list[CanonicalSample]) -> None:
        method = getattr(self.plugin, "prepare", None)
        if method:
            method([sample.public_request(self.required_inputs) for sample in samples])

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        value = self.plugin.decompile(request, artifact_dir)
        return self._normalize(value)

    def _normalize(self, value) -> DecompileResult:
        if isinstance(value, DecompileResult):
            value.backend_version = self.version
            return value
        if isinstance(value, str):
            return DecompileResult(
                success=bool(value.strip()),
                raw_output=value,
                code=value,
                reason=None if value.strip() else "decompile_empty_output",
                backend_version=self.version,
            )
        if isinstance(value, dict):
            value.setdefault("backend_version", self.version)
            return DecompileResult(**value)
        raise TypeError(f"Python plugin returned unsupported value: {type(value).__name__}")

    def decompile_many(self, requests, artifact_dirs):
        method = getattr(self.plugin, "decompile_many", None)
        if not method:
            return super().decompile_many(requests, artifact_dirs)
        values = method(requests, artifact_dirs)
        if len(values) != len(requests):
            raise ValueError("Python plugin decompile_many returned a different number of results")
        return [self._normalize(value) for value in values]

    def close(self) -> None:
        method = getattr(self.plugin, "close", None)
        if method:
            method()
