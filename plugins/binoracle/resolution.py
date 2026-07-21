from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

try:
    # Python 3.11+ exposes ``enum.StrEnum``. Fall back to a small compat
    # shim on Python 3.10 (used by the Linux runner hosts) so the module
    # imports cleanly without changing the wire string of each status.
    from enum import StrEnum
except ImportError:  # pragma: no cover - exercised only on Python < 3.11
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        __str__ = str.__str__


class ResolutionStatus(StrEnum):
    INITIAL = "initial"
    STATIC_INFERRED = "static_inferred"
    CAPABILITY_CHECKED = "capability_checked"
    PROBED = "probed"
    FROZEN = "frozen"
    RETRYABLE_REJECTED = "retryable_rejected"
    RETRYABLE_UNSUPPORTED = "retryable_unsupported"
    AMBIGUOUS = "ambiguous"
    BEHAVIORAL_EQUIVALENCE_CLASS = "behavioral_equivalence_class"
    UNIDENTIFIABLE_FROM_BINARY = "unidentifiable_from_binary"
    UNVERIFIED = "unverified"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


TERMINAL_STATUSES = frozenset(
    {
        ResolutionStatus.FROZEN,
        ResolutionStatus.BEHAVIORAL_EQUIVALENCE_CLASS,
        ResolutionStatus.UNIDENTIFIABLE_FROM_BINARY,
        ResolutionStatus.UNVERIFIED,
        ResolutionStatus.BUDGET_EXHAUSTED,
        ResolutionStatus.FAILED,
    }
)

_ALLOWED_TRANSITIONS = {
    ResolutionStatus.INITIAL: {ResolutionStatus.STATIC_INFERRED, ResolutionStatus.FAILED},
    ResolutionStatus.STATIC_INFERRED: {
        ResolutionStatus.CAPABILITY_CHECKED,
        ResolutionStatus.FAILED,
    },
    ResolutionStatus.CAPABILITY_CHECKED: {
        ResolutionStatus.PROBED,
        ResolutionStatus.RETRYABLE_UNSUPPORTED,
        ResolutionStatus.UNVERIFIED,
        ResolutionStatus.FAILED,
    },
    ResolutionStatus.PROBED: {
        ResolutionStatus.FROZEN,
        ResolutionStatus.RETRYABLE_REJECTED,
        ResolutionStatus.AMBIGUOUS,
        ResolutionStatus.BUDGET_EXHAUSTED,
        ResolutionStatus.UNIDENTIFIABLE_FROM_BINARY,
        ResolutionStatus.FAILED,
    },
    ResolutionStatus.RETRYABLE_REJECTED: {
        ResolutionStatus.CAPABILITY_CHECKED,
        ResolutionStatus.PROBED,
        ResolutionStatus.BUDGET_EXHAUSTED,
        ResolutionStatus.UNVERIFIED,
        ResolutionStatus.FAILED,
    },
    ResolutionStatus.RETRYABLE_UNSUPPORTED: {
        ResolutionStatus.CAPABILITY_CHECKED,
        ResolutionStatus.UNVERIFIED,
        ResolutionStatus.FAILED,
    },
    ResolutionStatus.AMBIGUOUS: {
        ResolutionStatus.PROBED,
        ResolutionStatus.BEHAVIORAL_EQUIVALENCE_CLASS,
        ResolutionStatus.UNIDENTIFIABLE_FROM_BINARY,
        ResolutionStatus.BUDGET_EXHAUSTED,
        ResolutionStatus.UNVERIFIED,
        ResolutionStatus.FAILED,
    },
}


class ResolutionStateError(ValueError):
    pass


@dataclass(frozen=True)
class ResolutionBudget:
    max_rounds: int
    max_executions: int
    max_wall_seconds: float
    rounds_used: int = 0
    executions_used: int = 0
    wall_seconds_used: float = 0.0

    def __post_init__(self) -> None:
        if self.max_rounds < 0 or self.max_executions < 0 or self.max_wall_seconds < 0:
            raise ResolutionStateError("resolution budgets must be non-negative")
        if self.rounds_used < 0 or self.executions_used < 0 or self.wall_seconds_used < 0:
            raise ResolutionStateError("consumed budgets must be non-negative")

    @property
    def exhausted(self) -> bool:
        return (
            self.rounds_used >= self.max_rounds
            or self.executions_used >= self.max_executions
            or self.wall_seconds_used >= self.max_wall_seconds
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_rounds": self.max_rounds,
            "max_executions": self.max_executions,
            "max_wall_seconds": self.max_wall_seconds,
            "rounds_used": self.rounds_used,
            "executions_used": self.executions_used,
            "wall_seconds_used": self.wall_seconds_used,
            "exhausted": self.exhausted,
        }


@dataclass(frozen=True)
class HarnessResolutionState:
    sample_id: str
    status: ResolutionStatus = ResolutionStatus.INITIAL
    reasons: tuple[str, ...] = ()
    contract_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    next_action: str | None = None
    budget: ResolutionBudget = field(
        default_factory=lambda: ResolutionBudget(0, 0, 0.0)
    )
    round_index: int = 0

    def transition(
        self,
        status: ResolutionStatus,
        *,
        reasons: Iterable[str] = (),
        contract_ids: Iterable[str] | None = None,
        evidence_ids: Iterable[str] = (),
        next_action: str | None = None,
        budget: ResolutionBudget | None = None,
    ) -> "HarnessResolutionState":
        if status != self.status and status not in _ALLOWED_TRANSITIONS.get(self.status, set()):
            raise ResolutionStateError(f"illegal resolution transition: {self.status} -> {status}")
        return HarnessResolutionState(
            sample_id=self.sample_id,
            status=status,
            reasons=tuple(sorted(set(str(item) for item in reasons))),
            contract_ids=(
                self.contract_ids
                if contract_ids is None
                else tuple(sorted(set(str(item) for item in contract_ids)))
            ),
            evidence_ids=tuple(sorted(set(str(item) for item in evidence_ids))),
            next_action=next_action,
            budget=budget or self.budget,
            round_index=self.round_index + (status == ResolutionStatus.PROBED),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.harness-resolution.v1",
            "sample_id": self.sample_id,
            "status": self.status.value,
            "terminal": self.status in TERMINAL_STATUSES,
            "reasons": list(self.reasons),
            "contract_ids": list(self.contract_ids),
            "evidence_ids": list(self.evidence_ids),
            "next_action": self.next_action,
            "budget": self.budget.to_dict(),
            "round_index": self.round_index,
        }


def audit_threshold_gaps(
    score: dict[str, Any], *, min_safe_observations: int, thresholds: dict[str, float]
) -> dict[str, float]:
    components = dict(score.get("components") or {})
    gaps = {
        "safe_observations": float(
            max(0, min_safe_observations - int(score.get("safe_observation_count", 0)))
        )
    }
    for name, minimum in thresholds.items():
        gaps[name] = max(0.0, float(minimum) - float(components.get(name, 0.0)))
    return gaps
