from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Protocol

from .models import (
    CanonicalSample,
    DecompileRequest,
    DecompileResult,
    EvaluationEvidence,
    ProtocolDescriptor,
    ValidationResult,
)


class Executor(Protocol):
    def run(self, command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None): ...


class DatasetAdapter(Protocol):
    plugin_name: str

    def iter_samples(self) -> Iterable[CanonicalSample]: ...

    evaluation_protocol: "EvaluationProtocol"


class EvaluationProtocol(Protocol):
    descriptor: ProtocolDescriptor

    def validate_reference(self, sample: CanonicalSample, executor: Executor, workdir: Path) -> ValidationResult: ...

    def evaluate_candidate(
        self, sample: CanonicalSample, code: str, executor: Executor, workdir: Path
    ) -> EvaluationEvidence: ...

    def failure_evidence(self, reason: str, **details: Any) -> EvaluationEvidence: ...


class DecompilerBackend(Protocol):
    backend_id: str
    version: str

    def prepare(self, samples: list[CanonicalSample]) -> None: ...

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult: ...

    def decompile_many(
        self, requests: list[DecompileRequest], artifact_dirs: list[Path]
    ) -> list[DecompileResult]: ...

    def close(self) -> None: ...


class Metric(Protocol):
    name: str

    def evaluate(self, sample: CanonicalSample, evidence: EvaluationEvidence) -> bool | float | None: ...

    def aggregate(self, values: list[bool | float | None]) -> dict[str, Any]: ...


class Postprocessor(Protocol):
    name: str

    def process(self, code: str, sample: CanonicalSample, config: dict[str, Any]) -> tuple[str, dict[str, Any] | None]: ...
