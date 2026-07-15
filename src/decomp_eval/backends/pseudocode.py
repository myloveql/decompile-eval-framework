from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import DecompileRequest, DecompileResult
from .base import BaseBackend


class DatasetPseudocodeBackend(BaseBackend):
    """Evaluate a pseudocode view already stored in the selected dataset."""

    required_inputs = ("pseudocode",)

    def __init__(self, config: dict[str, Any], **_: Any):
        self.backend_id = config["id"]
        self.version = str(config.get("version", "dataset-view"))

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        pseudocode = request.pseudocode
        if pseudocode is None or not pseudocode.text.strip():
            return DecompileResult(
                success=False,
                reason="pseudocode_missing",
                backend_version=self.version,
            )
        return DecompileResult(
            success=True,
            raw_output=pseudocode.text,
            code=pseudocode.text,
            backend_version=pseudocode.version or self.version,
        )
