from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .auditor import verify_harness_manifest
from .contract_v2 import ContractGraphV2, ContractValidationError
from .protocol import InputCase
from .runtime import ABIRunner, RunnerBuild, RunnerError


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _hash_json(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hash_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _semantic_observation(value: dict[str, Any]) -> dict[str, Any]:
    """Remove diagnostic timing, which is not part of the frozen behavior policy."""
    result = dict(value)
    result.pop("elapsed_us", None)
    return result


def _probe_artifacts(contract_dir: Path) -> dict[str, dict[str, Any]]:
    """Load the materialized V2 exploration and holdout probe artifacts.

    A frozen manifest commits to these serialized records; callers must never
    recreate them from the seed or the current probe generator.
    """
    return {
        "exploration": {
            "plan_path": contract_dir / "probe_plan.jsonl",
            "observations_path": contract_dir / "original_observations.jsonl",
            "probes": _read_jsonl(contract_dir / "probe_plan.jsonl"),
            "observations": _read_jsonl(contract_dir / "original_observations.jsonl"),
        },
        "holdout": {
            "plan_path": contract_dir / "holdout_probe_plan.jsonl",
            "observations_path": contract_dir / "holdout_observations.jsonl",
            "probes": _read_jsonl(contract_dir / "holdout_probe_plan.jsonl"),
            "observations": _read_jsonl(contract_dir / "holdout_observations.jsonl"),
        },
    }


def _entry(run_dir: Path, public_path: Path) -> dict[str, Any] | None:
    artifact_dir = public_path.parent
    stage_dir = artifact_dir / "binoracle"
    harness = _read_json(stage_dir / "harness_manifest.json")
    if harness is None:
        return None
    public = _read_json(public_path, {})
    metadata = _read_json(artifact_dir / "binoracle_metadata.json", {})
    selected = _read_json(stage_dir / "selected_contract.json", {})
    try:
        selected_hash = ContractGraphV2.from_dict(selected).content_hash
    except (ContractValidationError, KeyError, TypeError, ValueError):
        selected_hash = None
    policy = _read_json(stage_dir / "observation_policy.json", {})
    contract_id = str(harness.get("contract_id") or "")
    contract_dir = stage_dir / "contracts" / contract_id
    artifacts = _probe_artifacts(contract_dir)
    exploration = artifacts["exploration"]
    holdout = artifacts["holdout"]
    is_v2 = harness.get("schema_version") == "binoracle.harness.v2"
    reasons: list[str] = []
    checks = {
        "manifest_content_hash": verify_harness_manifest(harness),
        "manifest_v2": is_v2,
        "status_frozen": harness.get("status") == "frozen",
        "mutation_forbidden": harness.get("mutation_after_freeze_allowed") is False,
        "metadata_frozen": metadata.get("harness_frozen") is True,
        "metadata_accepted": (
            metadata.get("contract_selection_status")
            in {"audit_accepted_frozen", "audit_accepted_holdout_frozen"}
        ),
        "selected_contract_id": selected.get("contract_id") == contract_id,
        "selected_contract_hash": selected_hash == harness.get("contract_hash"),
        "exploration_probe_plan_hash": (
            _hash_json(exploration["probes"]) == harness.get("probe_plan_hash")
        ),
        "holdout_probe_plan_hash": (
            _hash_json(holdout["probes"]) == harness.get("holdout_probe_plan_hash")
        ),
        "observation_policy_hash": (
            _hash_json(policy) == harness.get("observation_policy_hash")
        ),
        "exploration_probe_count": (
            len(exploration["probes"])
            == int(harness.get("exploration_probe_count", -1))
        ),
        "holdout_probe_count": (
            len(holdout["probes"]) == int(harness.get("holdout_probe_count", -1))
        ),
        "probe_count": (
            len(exploration["probes"]) + len(holdout["probes"])
            == int(harness.get("probe_count", -1))
        ),
        "exploration_observation_count": (
            len(exploration["observations"]) == len(exploration["probes"])
        ),
        "holdout_observation_count": (
            len(holdout["observations"]) == len(holdout["probes"])
        ),
        "original_runner_present": (contract_dir / "original_runner.x").is_file(),
    }
    reasons.extend(name for name, passed in checks.items() if not passed)
    return {
        "schema_version": "binoracle.phase3-baseline-entry.v2",
        "run_dir": str(run_dir),
        "artifact_dir": str(artifact_dir.relative_to(run_dir)),
        "sample_id": public.get("sample_id") or metadata.get("sample_id"),
        "source_group_id": public.get("source_group_id") or metadata.get("source_group_id"),
        "optimization": public.get("optimization") or metadata.get("optimization"),
        "contract_id": contract_id,
        "contract_hash": harness.get("contract_hash"),
        "harness_hash": harness.get("content_hash"),
        "probe_plan_hash": harness.get("probe_plan_hash"),
        "holdout_probe_plan_hash": harness.get("holdout_probe_plan_hash"),
        "observation_policy_hash": harness.get("observation_policy_hash"),
        "exploration_observations_sha256": _hash_file(exploration["observations_path"]),
        "holdout_observations_sha256": _hash_file(holdout["observations_path"]),
        "original_runner_sha256": _hash_file(contract_dir / "original_runner.x"),
        "exploration_probe_count": len(exploration["probes"]),
        "holdout_probe_count": len(holdout["probes"]),
        "probe_count": len(exploration["probes"]) + len(holdout["probes"]),
        "checks": checks,
        "valid": not reasons,
        "failure_reasons": reasons,
    }


def create_phase3_baseline(
    run_dirs: Iterable[Path], *, output_path: Path
) -> dict[str, Any]:
    resolved_runs = [path.resolve() for path in run_dirs]
    entries = [
        entry
        for run_dir in resolved_runs
        for public_path in sorted(
            (run_dir / "artifacts").rglob("binoracle_public_request.json")
        )
        if (entry := _entry(run_dir, public_path)) is not None
    ]
    failures = [entry for entry in entries if not entry["valid"]]
    reason_counts = Counter(
        reason for entry in failures for reason in entry["failure_reasons"]
    )
    core = {
        "schema_version": "binoracle.phase3-baseline.v2",
        "run_dirs": [str(path) for path in resolved_runs],
        "frozen_harnesses": len(entries),
        "valid_frozen_harnesses": len(entries) - len(failures),
        "invalid_frozen_harnesses": len(failures),
        "failure_reason_counts": dict(sorted(reason_counts.items())),
        "entries": entries,
    }
    manifest = {**core, "content_hash": _hash_json(core)}
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_phase3_baseline(manifest: dict[str, Any]) -> bool:
    expected = manifest.get("content_hash")
    core = dict(manifest)
    core.pop("content_hash", None)
    return (
        manifest.get("schema_version") == "binoracle.phase3-baseline.v2"
        and isinstance(expected, str)
        and expected == _hash_json(core)
    )


def replay_phase3_baseline(
    manifest_path: Path,
    *,
    output_path: Path,
    runner_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    manifest = _read_json(manifest_path, {})
    if not verify_phase3_baseline(manifest):
        raise ValueError("Phase 3 baseline manifest content hash is invalid")
    runner = ABIRunner(
        {
            "runner_execution_timeout_ms": 100,
            "max_executions": 1000,
            **(runner_config or {}),
        }
    )
    runner.prepare()
    results: list[dict[str, Any]] = []
    for entry in manifest.get("entries", []):
        mismatches: list[str] = []
        errors: list[str] = []
        executions = 0
        timing_changes = 0
        phase_executions = {"exploration": 0, "holdout": 0}
        if not entry.get("valid"):
            errors.append("baseline_entry_invalid")
        try:
            run_dir = Path(str(entry["run_dir"])).resolve()
            artifact_dir = run_dir / str(entry["artifact_dir"])
            stage_dir = artifact_dir / "binoracle"
            selected = ContractGraphV2.from_dict(
                _read_json(stage_dir / "selected_contract.json", {})
            )
            contract = selected.to_runner_contract()
            contract_dir = stage_dir / "contracts" / str(entry["contract_id"])
            artifacts = _probe_artifacts(contract_dir)
            for phase, expected_plan_hash, expected_observations_hash in (
                (
                    "exploration",
                    entry.get("probe_plan_hash"),
                    entry.get("exploration_observations_sha256"),
                ),
                (
                    "holdout",
                    entry.get("holdout_probe_plan_hash"),
                    entry.get("holdout_observations_sha256"),
                ),
            ):
                artifact = artifacts[phase]
                probes = artifact["probes"]
                expected_observations = artifact["observations"]
                if _hash_json(probes) != expected_plan_hash:
                    raise ValueError(f"{phase} frozen probe plan hash changed")
                if _hash_file(artifact["observations_path"]) != expected_observations_hash:
                    raise ValueError(f"{phase} frozen observations changed")
                if len(probes) != len(expected_observations):
                    raise ValueError(f"{phase} probe and observation counts differ")
                build = RunnerBuild(contract_dir / "original_runner.x", {})
                for probe, expected in zip(probes, expected_observations):
                    input_case = InputCase.from_dict(probe["input_case"], contract=contract)
                    actual, _ = runner.execute(
                        build,
                        contract=contract,
                        input_case=input_case,
                    )
                    executions += 1
                    phase_executions[phase] += 1
                    timing_changes += actual.get("elapsed_us") != expected.get("elapsed_us")
                    if _semantic_observation(actual) != _semantic_observation(expected):
                        mismatches.append(f"{phase}:{probe.get('probe_id') or executions - 1}")
        except (ContractValidationError, RunnerError, KeyError, OSError, ValueError) as error:
            errors.append(f"{type(error).__name__}: {error}")
        results.append(
            {
                "sample_id": entry.get("sample_id"),
                "run_dir": entry.get("run_dir"),
                "artifact_dir": entry.get("artifact_dir"),
                "executions": executions,
                "exploration_executions": phase_executions["exploration"],
                "holdout_executions": phase_executions["holdout"],
                "diagnostic_timing_changes": timing_changes,
                "mismatched_probe_ids": mismatches,
                "errors": errors,
                "replay_match": not mismatches and not errors,
            }
        )
    matches = sum(bool(value["replay_match"]) for value in results)
    core = {
        "schema_version": "binoracle.phase3-baseline-replay.v2",
        "baseline_manifest": str(manifest_path),
        "baseline_content_hash": manifest.get("content_hash"),
        "harnesses_total": len(results),
        "harnesses_replay_match": matches,
        "harnesses_replay_mismatch": len(results) - matches,
        "replay_match_rate": matches / len(results) if results else None,
        "executions": sum(int(value["executions"]) for value in results),
        "exploration_executions": sum(
            int(value["exploration_executions"]) for value in results
        ),
        "holdout_executions": sum(
            int(value["holdout_executions"]) for value in results
        ),
        "diagnostic_timing_changes": sum(
            int(value["diagnostic_timing_changes"]) for value in results
        ),
        "results": results,
    }
    report = {**core, "content_hash": _hash_json(core)}
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


__all__ = [
    "create_phase3_baseline",
    "replay_phase3_baseline",
    "verify_phase3_baseline",
]
