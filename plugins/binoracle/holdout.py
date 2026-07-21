from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .contract_v2 import ContractGraphV2
from .probes import ProbeCase, generate_probe_plan


@dataclass(frozen=True)
class HoldoutPlan:
    commitment: dict[str, object]
    probes: tuple[ProbeCase, ...]


def _holdout_seed(contract: ContractGraphV2, seed: int) -> int:
    material = f"binoracle-holdout-v1:{contract.content_hash}:{seed}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def commit_holdout(
    contract: ContractGraphV2,
    *,
    probe_seed: int,
    max_executions: int,
    repetitions: int,
) -> HoldoutPlan:
    """Commit a deterministic holdout plan without exposing it to exploration."""
    from .auditor import holdout_commitment

    seed = _holdout_seed(contract, probe_seed)
    commitment = holdout_commitment(contract=contract, probe_seed=seed)
    probes = generate_probe_plan(
        contract,
        base_seed=seed,
        max_executions=max_executions,
        repetitions=repetitions,
    )
    return HoldoutPlan(commitment=commitment, probes=probes)
