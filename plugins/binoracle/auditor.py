from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from .contract_v2 import ContractGraphV2
from .probes import ProbeCase


def _hash_json(value: Any) -> str:
    import json

    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditThresholds:
    min_safe_observations: int = 4
    min_valid: float = 0.90
    min_stable: float = 1.0
    min_effect: float = 0.05
    min_boundary: float = 0.90
    min_score_margin: float = 0.05

    @classmethod
    def from_config(cls, value: dict[str, Any]) -> "AuditThresholds":
        result = cls(int(value.get("audit_min_safe_observations", 4)), float(value.get("audit_min_valid", .90)), float(value.get("audit_min_stable", 1.0)), float(value.get("audit_min_effect", .05)), float(value.get("audit_min_boundary", .90)), float(value.get("audit_min_score_margin", .05)))
        if result.min_safe_observations <= 0:
            raise ValueError("audit_min_safe_observations must be positive")
        if any(not 0 <= getattr(result, name) <= 1 for name in ("min_valid", "min_stable", "min_effect", "min_boundary", "min_score_margin")):
            raise ValueError("audit thresholds must be between 0 and 1")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {"min_safe_observations": self.min_safe_observations, "min_valid": self.min_valid, "min_stable": self.min_stable, "min_effect": self.min_effect, "min_boundary": self.min_boundary, "min_score_margin": self.min_score_margin}


@dataclass(frozen=True)
class AuditDecision:
    decision: str
    selected_contract: str | None
    competing_contracts: tuple[str, ...]
    reasons: tuple[str, ...]
    thresholds: AuditThresholds
    threshold_gaps: dict[str, dict[str, float]]

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "binoracle.contract-audit.v2", "decision": self.decision, "selected_contract": self.selected_contract, "competing_contracts": list(self.competing_contracts), "reasons": list(self.reasons), "thresholds": self.thresholds.to_dict(), "threshold_gaps": self.threshold_gaps}


def _static_evidence(contract: ContractGraphV2) -> set[str]:
    result = set(contract.evidence_ids) | set(contract.return_spec.evidence_ids)
    for item in (*contract.arguments, *contract.objects):
        result.update(item.evidence_ids)
    return result


def _gaps(score: dict[str, Any], thresholds: AuditThresholds) -> dict[str, float]:
    components = dict(score.get("components") or {})
    result = {"safe_observations": float(max(0, thresholds.min_safe_observations - int(score.get("safe_observation_count", 0))))}
    for name, minimum in (("valid", thresholds.min_valid), ("stable", thresholds.min_stable), ("effect", thresholds.min_effect), ("boundary", thresholds.min_boundary)):
        result[name] = max(0.0, minimum - float(components.get(name, 0.0)))
    return result


def audit_contracts(candidates: Iterable[ContractGraphV2], score_records: Iterable[dict[str, Any]], *, thresholds: AuditThresholds) -> AuditDecision:
    by_id = {item.contract_id: item for item in candidates}
    accepted, reasons, gaps = [], [], {}
    for score in score_records:
        contract_id = str(score.get("contract_id", ""))
        contract = by_id.get(contract_id)
        if score.get("status") != "dynamic_scored":
            reasons.append(f"{contract_id}:not_dynamically_scored")
            continue
        if contract is None:
            reasons.append(f"{contract_id}:missing_contract")
            continue
        current = _gaps(score, thresholds)
        gaps[contract_id] = current
        failures = [name + "_below_threshold" if name != "safe_observations" else "insufficient_safe_observations" for name, gap in current.items() if gap > 0]
        if not _static_evidence(contract):
            failures.append("missing_static_evidence")
        if contract.unsupported_reasons:
            failures.append("contract_has_unsupported_reasons")
        if failures:
            reasons.extend(f"{contract_id}:{item}" for item in failures)
        else:
            accepted.append(score)
    if not accepted:
        return AuditDecision("rejected", None, (), tuple(sorted(set(reasons))) or ("no_candidate",), thresholds, gaps)
    accepted.sort(key=lambda item: (-float(item["total"]), str(item["contract_id"])))
    best = accepted[0]
    competitors = [item for item in accepted[1:] if float(best["total"]) - float(item["total"]) < thresholds.min_score_margin]
    if competitors:
        return AuditDecision("ambiguous", None, tuple(str(item["contract_id"]) for item in [best, *competitors]), ("score_margin_below_threshold",), thresholds, gaps)
    return AuditDecision("accepted", str(best["contract_id"]), (), ("all_audit_thresholds_satisfied",), thresholds, gaps)


def holdout_commitment(*, contract: ContractGraphV2, probe_seed: int, generator_version: str = "binoracle-probe-v2") -> dict[str, Any]:
    core = {"schema_version": "binoracle.holdout-commitment.v1", "contract_hash": contract.content_hash, "probe_seed": probe_seed, "generator_version": generator_version}
    return {**core, "content_hash": _hash_json(core)}


def freeze_harness_manifest(*, contract: ContractGraphV2, probes: tuple[ProbeCase, ...], observation_policy: dict[str, Any], runner_version: str, target_function: str, probe_seed: int, resource_limits: dict[str, Any], holdout_probes: tuple[ProbeCase, ...] = (), holdout: dict[str, Any] | None = None, capability_report: dict[str, Any] | None = None) -> dict[str, Any]:
    exploration_values = [item.to_dict() for item in probes]
    holdout_values = [item.to_dict() for item in holdout_probes]
    core = {"schema_version": "binoracle.harness.v2", "status": "frozen", "target_function": target_function, "contract_id": contract.contract_id, "contract_hash": contract.content_hash, "probe_plan_hash": _hash_json(exploration_values), "exploration_probe_count": len(probes), "holdout_probe_plan_hash": _hash_json(holdout_values), "holdout_probe_count": len(holdout_probes), "holdout_commitment": holdout, "capability_report": capability_report, "observation_policy_hash": _hash_json(observation_policy), "runner_version": runner_version, "probe_seed": probe_seed, "probe_count": len(probes) + len(holdout_probes), "resource_limits": dict(resource_limits), "mutation_after_freeze_allowed": False}
    return {**core, "content_hash": _hash_json(core)}


def verify_harness_manifest(manifest: dict[str, Any]) -> bool:
    expected = manifest.get("content_hash")
    core = dict(manifest)
    core.pop("content_hash", None)
    return isinstance(expected, str) and expected == _hash_json(core)
