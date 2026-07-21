from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


class ProposalValidationError(ValueError):
    pass


_FORBIDDEN_FIELDS = frozenset(
    {
        "source",
        "source_truth",
        "official_signature",
        "wrapper",
        "hidden_test",
        "evaluator_output",
        "ground_truth",
    }
)


def _require_evidence_ids(values: Iterable[Any], known_evidence_ids: set[str]) -> tuple[str, ...]:
    result = tuple(str(value) for value in values)
    if not result:
        raise ProposalValidationError("proposal requires at least one evidence ID")
    unknown = sorted(set(result) - known_evidence_ids)
    if unknown:
        raise ProposalValidationError("proposal references unknown evidence IDs: " + ", ".join(unknown))
    return result


def _reject_private_fields(value: Any) -> None:
    if isinstance(value, dict):
        forbidden = _FORBIDDEN_FIELDS.intersection(value)
        if forbidden:
            raise ProposalValidationError("proposal includes prohibited private field: " + sorted(forbidden)[0])
        for item in value.values():
            _reject_private_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_private_fields(item)


@dataclass(frozen=True)
class ContractProposal:
    proposed_contract: dict[str, Any]
    evidence_ids: tuple[str, ...]
    confidence: float

    @classmethod
    def from_dict(cls, value: dict[str, Any], *, known_evidence_ids: Iterable[str]) -> "ContractProposal":
        _reject_private_fields(value)
        confidence = float(value.get("confidence", 0.0))
        if not 0.0 <= confidence <= 1.0:
            raise ProposalValidationError("proposal confidence must be between 0 and 1")
        payload = dict(value.get("proposed_contract", {}))
        if not payload:
            raise ProposalValidationError("proposal must contain proposed_contract")
        return cls(payload, _require_evidence_ids(value.get("evidence_ids", []), set(known_evidence_ids)), confidence)


@dataclass(frozen=True)
class ProbeIntent:
    strategy: str
    evidence_ids: tuple[str, ...]
    rationale: str
    confidence: float

    @classmethod
    def from_dict(cls, value: dict[str, Any], *, known_evidence_ids: Iterable[str]) -> "ProbeIntent":
        _reject_private_fields(value)
        strategy = str(value.get("strategy", ""))
        if strategy not in {"effect_boundary", "boundary_pair", "stability_replay", "safe_neighborhood"}:
            raise ProposalValidationError("unsupported probe intent strategy")
        confidence = float(value.get("confidence", 0.0))
        if not 0.0 <= confidence <= 1.0:
            raise ProposalValidationError("probe intent confidence must be between 0 and 1")
        rationale = str(value.get("rationale", ""))
        if not rationale:
            raise ProposalValidationError("probe intent requires rationale")
        return cls(strategy, _require_evidence_ids(value.get("evidence_ids", []), set(known_evidence_ids)), rationale, confidence)
