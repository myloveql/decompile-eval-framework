from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from .auditor import verify_harness_manifest


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
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _wilson_95(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    radius = (
        z
        * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total))
        / denominator
    )
    return [max(0.0, center - radius), min(1.0, center + radius)]


def _artifact_sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _frozen_artifact_checks(stage_dir: Path, harness: dict[str, Any] | None) -> dict[str, bool]:
    if harness is None:
        return {
            "manifest_v2": False,
            "exploration_plan": False,
            "holdout_plan": False,
            "exploration_observations": False,
            "holdout_observations": False,
        }
    contract_dir = stage_dir / "contracts" / str(harness.get("contract_id") or "")
    exploration_plan = _read_jsonl(contract_dir / "probe_plan.jsonl")
    holdout_plan = _read_jsonl(contract_dir / "holdout_probe_plan.jsonl")
    exploration_observations = _read_jsonl(contract_dir / "original_observations.jsonl")
    holdout_observations = _read_jsonl(contract_dir / "holdout_observations.jsonl")
    return {
        "manifest_v2": harness.get("schema_version") == "binoracle.harness.v2",
        "exploration_plan": (
            _hash_json(exploration_plan) == harness.get("probe_plan_hash")
            and len(exploration_plan) == int(harness.get("exploration_probe_count", -1))
        ),
        "holdout_plan": (
            _hash_json(holdout_plan) == harness.get("holdout_probe_plan_hash")
            and len(holdout_plan) == int(harness.get("holdout_probe_count", -1))
        ),
        "exploration_observations": len(exploration_observations) == len(exploration_plan),
        "holdout_observations": len(holdout_observations) == len(holdout_plan),
    }


def _terminal_status(metadata: dict[str, Any], differential: dict[str, Any]) -> str:
    if not metadata.get("harness_frozen"):
        reason = str(metadata.get("unsupported_reason") or metadata.get("stop_reason") or "")
        if reason.startswith("binoracle_unsupported") or "no_runnable_candidate" in reason:
            return "unsupported"
        selection = str(metadata.get("contract_selection_status") or "")
        if selection == "audit_ambiguous":
            return "harness_ambiguous"
        if selection == "audit_rejected":
            return "harness_rejected"
        return "harness_not_frozen"
    if not differential:
        return "differential_missing"
    if not differential.get("candidate_compile"):
        return "candidate_compile_failed"
    if differential.get("candidate_compile_gate") is False:
        return "candidate_compile_gate_failed"
    if not differential.get("candidate_link"):
        return "candidate_link_failed"
    if differential.get("differential_pass"):
        return "differential_equivalent"
    return "behavior_mismatch"


def summarize_phase3_differential(
    run_dir: Path, *, output_dir: Path | None = None
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    output_dir = (output_dir or run_dir / "binoracle_phase3").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for public_path in sorted(
        (run_dir / "artifacts").rglob("binoracle_public_request.json")
    ):
        artifact_dir = public_path.parent
        stage_dir = artifact_dir / "binoracle"
        public = _read_json(public_path, {})
        metadata = _read_json(artifact_dir / "binoracle_metadata.json", {})
        differential = _read_json(stage_dir / "differential_summary.json", {})
        repair = _read_json(stage_dir / "repair_summary.json", {})
        repair_iterations = repair.get("iterations", [])
        initial_differential = (
            repair_iterations[0].get("differential", {})
            if repair_iterations
            else differential
        )
        harness = _read_json(stage_dir / "harness_manifest.json")
        frozen_artifacts = _frozen_artifact_checks(stage_dir, harness)
        records.append(
            {
                "schema_version": "binoracle.phase3-differential-result.v1",
                "sample_id": public.get("sample_id") or metadata.get("sample_id"),
                "source_group_id": public.get("source_group_id")
                or metadata.get("source_group_id"),
                "optimization": public.get("optimization") or metadata.get("optimization"),
                "status": _terminal_status(metadata, differential),
                "harness_frozen": bool(metadata.get("harness_frozen")),
                "harness_manifest_verified": (
                    verify_harness_manifest(harness) if harness is not None else False
                ),
                "frozen_probe_artifacts_verified": all(frozen_artifacts.values()),
                "frozen_probe_artifact_checks": frozen_artifacts,
                "candidate_compile": bool(differential.get("candidate_compile")),
                "candidate_compile_gate": differential.get("candidate_compile_gate"),
                "candidate_link": bool(differential.get("candidate_link")),
                "differential_pass": bool(differential.get("differential_pass")),
                "tests_total": int(differential.get("tests_total", 0)),
                "tests_passed": int(differential.get("tests_passed", 0)),
                "differences": int(differential.get("differences", 0)),
                "difference_kinds": differential.get("difference_kinds", {}),
                "evidence_packages": int(differential.get("evidence_packages", 0)),
                "minimized_counterexamples": int(
                    differential.get("minimized_counterexamples", 0)
                ),
                "executions": int(metadata.get("executions", 0)),
                "stop_reason": metadata.get("stop_reason"),
                "initial_candidate_compile": bool(
                    initial_differential.get("candidate_compile")
                ),
                "initial_candidate_link": bool(initial_differential.get("candidate_link")),
                "initial_differential_pass": bool(
                    initial_differential.get("differential_pass")
                ),
                "repair_status": repair.get("status"),
                "repair_reason": repair.get("reason"),
                "repair_iterations": int(repair.get("repair_iterations", 0)),
                "harness_mutated": bool(repair.get("harness_mutated", False)),
            }
        )

    # Framework failures can occur before BinOracle writes its public request. Keep
    # them in the selected-set denominator by reconciling against results.jsonl.
    framework_results = []
    results_path = run_dir / "results.jsonl"
    if results_path.is_file():
        framework_results = [
            json.loads(line)
            for line in results_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    recorded_ids = {str(value["sample_id"]) for value in records}
    for result in framework_results:
        sample_id = str(result.get("sample_id") or "")
        if not sample_id or sample_id in recorded_ids:
            continue
        reason = str(result.get("reason") or "framework_failure")
        status = (
            "unsupported"
            if "no_runnable_candidate" in reason or reason.startswith("binoracle_unsupported")
            else "framework_failed_before_artifacts"
        )
        records.append(
            {
                "schema_version": "binoracle.phase3-differential-result.v1",
                "sample_id": sample_id,
                "source_group_id": result.get("source_group_id"),
                "optimization": result.get("optimization"),
                "status": status,
                "harness_frozen": False,
                "harness_manifest_verified": False,
                "candidate_compile": False,
                "candidate_compile_gate": None,
                "candidate_link": False,
                "differential_pass": False,
                "tests_total": 0,
                "tests_passed": 0,
                "differences": 0,
                "difference_kinds": {},
                "evidence_packages": 0,
                "minimized_counterexamples": 0,
                "executions": 0,
                "stop_reason": reason,
                "initial_candidate_compile": False,
                "initial_candidate_link": False,
                "initial_differential_pass": False,
                "repair_status": None,
                "repair_reason": None,
                "repair_iterations": 0,
                "harness_mutated": False,
            }
        )
    records.sort(key=lambda value: str(value["sample_id"]))

    def summarize(values: list[dict[str, Any]]) -> dict[str, Any]:
        frozen = [value for value in values if value["harness_frozen"]]
        compiled = [value for value in frozen if value["candidate_compile"]]
        compile_gate_applicable = [
            value for value in frozen if value["candidate_compile_gate"] is not None
        ]
        compile_gate_passed = [
            value for value in compile_gate_applicable if value["candidate_compile_gate"]
        ]
        linked = [value for value in frozen if value["candidate_link"]]
        equivalent = [value for value in frozen if value["differential_pass"]]
        initial_compiled = [
            value for value in frozen if value["initial_candidate_compile"]
        ]
        initial_equivalent = [
            value for value in frozen if value["initial_differential_pass"]
        ]
        repaired = [value for value in frozen if value["repair_iterations"] > 0]
        net_compile_repairs = [
            value
            for value in frozen
            if not value["initial_candidate_compile"] and value["candidate_compile"]
        ]
        net_behavior_repairs = [
            value
            for value in frozen
            if not value["initial_differential_pass"] and value["differential_pass"]
        ]
        regressions = [
            value
            for value in frozen
            if value["initial_differential_pass"] and not value["differential_pass"]
        ]
        kind_counts = Counter(
            kind
            for value in values
            for kind, count in value["difference_kinds"].items()
            for _ in range(int(count))
        )
        return {
            "total": len(values),
            "status_counts": dict(
                sorted(Counter(value["status"] for value in values).items())
            ),
            "frozen_harnesses": len(frozen),
            "frozen_manifest_integrity_rate": _ratio(
                sum(value["harness_manifest_verified"] for value in frozen), len(frozen)
            ),
            "candidate_compile_rate_fixed_denominator": _ratio(
                len(compiled), len(values)
            ),
            "candidate_compile_rate_fixed_denominator_ci95": _wilson_95(
                len(compiled), len(values)
            ),
            "candidate_compile_rate_frozen_denominator": _ratio(
                len(compiled), len(frozen)
            ),
            "candidate_compile_gate_enabled_harnesses": len(compile_gate_applicable),
            "candidate_compile_gate_passes": len(compile_gate_passed),
            "candidate_compile_gate_pass_rate": _ratio(
                len(compile_gate_passed), len(compile_gate_applicable)
            ),
            "candidate_link_rate_fixed_denominator": _ratio(len(linked), len(values)),
            "candidate_link_rate_frozen_denominator": _ratio(len(linked), len(frozen)),
            "differential_pass_rate_fixed_denominator": _ratio(
                len(equivalent), len(values)
            ),
            "differential_pass_rate_fixed_denominator_ci95": _wilson_95(
                len(equivalent), len(values)
            ),
            "differential_pass_rate_frozen_denominator": _ratio(
                len(equivalent), len(frozen)
            ),
            "differential_pass_rate_frozen_denominator_ci95": _wilson_95(
                len(equivalent), len(frozen)
            ),
            "initial_candidate_compile_rate_frozen_denominator": _ratio(
                len(initial_compiled), len(frozen)
            ),
            "initial_differential_pass_rate_frozen_denominator": _ratio(
                len(initial_equivalent), len(frozen)
            ),
            "repair_attempted": len(repaired),
            "net_compile_repairs": len(net_compile_repairs),
            "net_behavior_repairs": len(net_behavior_repairs),
            "introduced_regressions": len(regressions),
            "harness_mutation_violations": sum(
                value["harness_mutated"] for value in frozen
            ),
            "repair_status_counts": dict(
                sorted(
                    Counter(
                        str(value["repair_status"])
                        for value in frozen
                        if value["repair_status"] is not None
                    ).items()
                )
            ),
            "difference_kind_counts": dict(sorted(kind_counts.items())),
            "tests_total": sum(value["tests_total"] for value in values),
            "tests_passed": sum(value["tests_passed"] for value in values),
            "differences": sum(value["differences"] for value in values),
            "evidence_packages": sum(value["evidence_packages"] for value in values),
            "minimized_counterexamples": sum(
                value["minimized_counterexamples"] for value in values
            ),
            "executions": sum(value["executions"] for value in values),
        }

    optimizations = sorted({str(value["optimization"]) for value in records})
    framework_compile = sum(bool(value.get("compile_pass")) for value in framework_results)
    framework_link = sum(bool(value.get("link_pass")) for value in framework_results)
    framework_behavior = sum(
        bool(value.get("behavioral_pass")) for value in framework_results
    )
    framework_total = len(framework_results)
    report = {
        "schema_version": "binoracle.phase3-differential-summary.v1",
        "run_dir": str(run_dir),
        "overall": summarize(records),
        "by_optimization": {
            optimization: summarize(
                [
                    value
                    for value in records
                    if str(value["optimization"]) == optimization
                ]
            )
            for optimization in optimizations
        },
        "external_evaluator": {
            "denominator_policy": "all framework results in the fixed selection",
            "total": framework_total,
            "compile_passes": framework_compile,
            "compile_pass_rate": _ratio(framework_compile, framework_total),
            "compile_pass_rate_ci95": _wilson_95(framework_compile, framework_total),
            "link_passes": framework_link,
            "link_pass_rate": _ratio(framework_link, framework_total),
            "link_pass_rate_ci95": _wilson_95(framework_link, framework_total),
            "behavioral_passes": framework_behavior,
            "behavioral_pass_rate": _ratio(framework_behavior, framework_total),
            "behavioral_pass_rate_ci95": _wilson_95(
                framework_behavior, framework_total
            ),
            "reason_counts": dict(
                sorted(
                    Counter(str(value.get("reason") or "pass") for value in framework_results).items()
                )
            ),
            "tests_total": sum(int(value.get("tests_total") or 0) for value in framework_results),
            "tests_passed": sum(
                int(value.get("tests_passed") or 0) for value in framework_results
            ),
        },
    }
    (output_dir / "differential_results.jsonl").write_text(
        "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in records),
        encoding="utf-8",
    )
    (output_dir / "differential_summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (output_dir / "differential_summary.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fieldnames = [
            "optimization",
            "total",
            "frozen_harnesses",
            "candidate_compile_rate_fixed_denominator",
            "candidate_link_rate_fixed_denominator",
            "differential_pass_rate_fixed_denominator",
            "candidate_compile_rate_frozen_denominator",
            "candidate_compile_gate_enabled_harnesses",
            "candidate_compile_gate_passes",
            "candidate_compile_gate_pass_rate",
            "candidate_link_rate_frozen_denominator",
            "differential_pass_rate_frozen_denominator",
            "initial_candidate_compile_rate_frozen_denominator",
            "initial_differential_pass_rate_frozen_denominator",
            "repair_attempted",
            "net_compile_repairs",
            "net_behavior_repairs",
            "introduced_regressions",
            "harness_mutation_violations",
            "differences",
            "executions",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerow({"optimization": "overall", **report["overall"]})
        for optimization, value in report["by_optimization"].items():
            writer.writerow({"optimization": optimization, **value})
    return report


__all__ = ["summarize_phase3_differential"]
