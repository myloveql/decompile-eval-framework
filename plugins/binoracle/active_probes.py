from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from .contract_v2 import ContractGraphV2
from .probes import ProbeCase, generate_probe_plan


@dataclass(frozen=True)
class ProbeGeneration:
    strategy: str
    reason_codes: tuple[str, ...]
    probes: tuple[ProbeCase, ...]
    no_information_rounds: int

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "binoracle.active-probes.v1", "strategy": self.strategy, "reason_codes": list(self.reason_codes), "probes": [probe.to_dict() for probe in self.probes], "no_information_rounds": self.no_information_rounds}


def _derived_seed(base_seed: int, contract_id: str, round_index: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{base_seed}:{contract_id}:{round_index}".encode()).digest()[:4], "big")


def generate_failure_directed_probes(contract: ContractGraphV2, audit_reasons: Iterable[str], *, base_seed: int, round_index: int, max_executions: int, repetitions: int = 2) -> ProbeGeneration:
    reasons = tuple(sorted(set(str(reason).split(":")[-1] for reason in audit_reasons)))
    strategy = "safe_neighborhood"
    if "effect_below_threshold" in reasons:
        strategy = "effect_boundary"
    elif "boundary_below_threshold" in reasons:
        strategy = "boundary_pair"
    elif "stable_below_threshold" in reasons:
        strategy = "stability_replay"
    # The baseline generator already includes safe, boundary, and repeated cases.
    # Rotating its seed deterministically adds only bounded, auditable evidence.
    probes = generate_probe_plan(contract, base_seed=_derived_seed(base_seed, contract.contract_id, round_index), max_executions=max_executions, repetitions=repetitions)
    return ProbeGeneration(strategy, reasons, probes, 0 if probes else 1)


def should_stop_active_probing(*, no_information_rounds: int, risk_upper_bound: float, risk_limit: float, budget_exhausted: bool) -> str | None:
    if budget_exhausted:
        return "budget_exhausted"
    if risk_upper_bound > risk_limit:
        return "risk_limit_exceeded"
    if no_information_rounds >= 2:
        return "no_new_information"
    return None
