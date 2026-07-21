from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .contract_v2 import ContractGraphV2
from .probes import ProbeCase, generate_probe_plan


@dataclass(frozen=True)
class BehavioralContractEquivalenceClass:
    contract_ids: tuple[str, ...]
    behavioral_contract_id: str
    reason: str
    safe_probe_count: int

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "binoracle.behavioral-equivalence.v1", "status": "unidentifiable_from_binary", "behavioral_contract": self.behavioral_contract_id, "source_level_alternatives": list(self.contract_ids), "distinguishing_probe_found": False, "safe_probe_count": self.safe_probe_count, "reason": self.reason}


def generate_discriminative_probes(candidates: Iterable[ContractGraphV2], *, base_seed: int, max_executions: int, repetitions: int = 2) -> tuple[ProbeCase, ...]:
    candidates = tuple(candidates)
    if not candidates:
        return ()
    # Contracts with different primary ABI/object choices produce different plan
    # shapes. A fixed merged prefix is deterministic and safe under each candidate.
    plans = [generate_probe_plan(item, base_seed=base_seed, max_executions=max_executions, repetitions=repetitions) for item in candidates]
    return plans[0] if len(plans) == 1 else tuple(probe for plan in plans for probe in plan)[:max_executions]


def equivalent_if_no_disagreement(candidates: Iterable[ContractGraphV2], *, safe_probe_count: int) -> BehavioralContractEquivalenceClass:
    values = tuple(sorted(item.contract_id for item in candidates))
    return BehavioralContractEquivalenceClass(values, values[0], "all alternatives induce identical observable machine behavior", safe_probe_count)
