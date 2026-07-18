from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AssemblyInput:
    text: str
    syntax: str
    view: str


@dataclass(frozen=True)
class BinaryInput:
    path: str
    sha256: str | None = None
    format: str | None = None
    architecture: str | None = None


@dataclass(frozen=True)
class PseudocodeInput:
    text: str
    view: str
    producer: str
    version: str | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class CandidateCompileContext:
    """Public, test-free context for recompiling a generated candidate."""

    language: str
    compiler: str
    flags: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    prelude: str = ""


@dataclass(frozen=True)
class OracleContext:
    """Private benchmark feedback exposed only to explicitly oracle-assisted backends."""

    protocol: str
    payload: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class CanonicalSample:
    dataset_id: str
    split: str
    sample_id: str
    source_group_id: str
    function_name: str
    language: str
    optimization: str
    assembly: AssemblyInput
    content_hash: str
    binary: BinaryInput | None = None
    pseudocode: PseudocodeInput | None = None
    compile_context: CandidateCompileContext | None = None
    oracle_context: OracleContext | None = field(default=None, repr=False)
    metadata: dict[str, Any] = field(default_factory=dict)
    private_payload: dict[str, Any] = field(default_factory=dict, repr=False)

    def public_request(self, allowed_inputs: tuple[str, ...] | None = None) -> "DecompileRequest":
        allowed = set(
            ("assembly", "binary", "pseudocode") if allowed_inputs is None else allowed_inputs
        )
        return DecompileRequest(
            dataset_id=self.dataset_id,
            split=self.split,
            sample_id=self.sample_id,
            source_group_id=self.source_group_id,
            function_name=self.function_name,
            language=self.language,
            optimization=self.optimization,
            assembly=self.assembly if "assembly" in allowed else AssemblyInput(
                text="", syntax=self.assembly.syntax, view=self.assembly.view
            ),
            binary=self.binary if "binary" in allowed else None,
            pseudocode=self.pseudocode if "pseudocode" in allowed else None,
            compile_context=(
                self.compile_context if "compile_context" in allowed else None
            ),
            oracle_context=(
                self.oracle_context if "oracle_context" in allowed else None
            ),
            metadata=self.metadata,
        )


@dataclass(frozen=True)
class DecompileRequest:
    dataset_id: str
    split: str
    sample_id: str
    source_group_id: str
    function_name: str
    language: str
    optimization: str
    assembly: AssemblyInput
    metadata: dict[str, Any]
    binary: BinaryInput | None = None
    pseudocode: PseudocodeInput | None = None
    compile_context: CandidateCompileContext | None = None
    oracle_context: OracleContext | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DecompileResult:
    success: bool
    raw_output: str = ""
    code: str = ""
    reason: str | None = None
    log: str = ""
    elapsed_seconds: float = 0.0
    backend_version: str = "unknown"


@dataclass
class ProcessedCode:
    raw_output: str
    code: str
    actions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float
    timed_out: bool = False


@dataclass
class EvaluationEvidence:
    protocol_id: str = "unknown"
    protocol_version: str = "unknown"
    capabilities: tuple[str, ...] = ()
    compile_pass: bool = False
    link_pass: bool = False
    behavioral_pass: bool = False
    reason: str | None = None
    tests_total: int = 0
    tests_passed: int = 0
    elapsed_seconds: float = 0.0
    logs: dict[str, Any] = field(default_factory=dict)
    stages: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def recompilable(self) -> bool:
        return self.compile_pass and self.link_pass


@dataclass(frozen=True)
class MetricContext:
    candidate_code: str
    candidate_sha256: str
    artifact_dir: str
    generation_key: str
    candidate_key: str
    evaluation_key: str | None


@dataclass
class ValidationResult:
    sample_id: str
    valid: bool
    evidence: EvaluationEvidence


@dataclass(frozen=True)
class ProtocolDescriptor:
    protocol_id: str
    version: str
    description: str
    capabilities: tuple[str, ...]
    compile_unit: str
    test_granularity: str
    comparator: str
    denominator_policy: str = "all selected reference-valid samples"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_artifact_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
