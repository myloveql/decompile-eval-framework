from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class BinaryFacts:
    path: str
    sha256: str
    size_bytes: int
    elf_class: int
    endianness: str
    elf_type: str
    machine: str
    target_function: str
    target: dict[str, Any] = field(default_factory=dict)
    sections: tuple[dict[str, Any], ...] = ()
    symbols: tuple[dict[str, Any], ...] = ()
    relocations: tuple[dict[str, Any], ...] = ()
    undefined_symbols: tuple[str, ...] = ()
    global_objects: tuple[dict[str, Any], ...] = ()
    dependencies: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ObjectSpec:
    object_id: str
    argument_slot: str
    min_size: int
    alignment: int = 1
    reads: tuple[tuple[int, int], ...] = ()
    writes: tuple[tuple[int, int], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reads"] = [list(item) for item in self.reads]
        value["writes"] = [list(item) for item in self.writes]
        return value


@dataclass(frozen=True)
class ArgumentSpec:
    slot: str
    kind_candidates: tuple[str, ...]
    confidence: float
    evidence: tuple[str, ...] = ()
    object_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReturnSpec:
    kind: str
    confidence: float
    observable: bool
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ContractGraph:
    contract_id: str
    abi: str
    arguments: tuple[ArgumentSpec, ...]
    return_spec: ReturnSpec
    objects: tuple[ObjectSpec, ...] = ()
    dependencies: tuple[str, ...] = ()
    confidence: float = 0.0
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "abi": self.abi,
            "arguments": [item.to_dict() for item in self.arguments],
            "return": self.return_spec.to_dict(),
            "objects": [item.to_dict() for item in self.objects],
            "dependencies": list(self.dependencies),
            "confidence": self.confidence,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ObservationPolicy:
    compare_process_status: bool = True
    compare_return: bool = False
    compare_reachable_memory: bool = True
    compare_globals: bool = True
    compare_external_calls: bool = False
    compare_coverage: bool = True
    rationale: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
