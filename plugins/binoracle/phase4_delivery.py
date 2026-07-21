"""Phase 4 delivery artifact generator (§17 deliverables 6 + 8).

Produces the artifacts required by section 17 of the BinOracle Phase 4 plan:

  * ``state_transition_matrix.csv`` — every (source_status, target_status)
    transition observed in the run plus its count.
  * ``group_level_coverage.csv`` — per-source-group coverage so the report
    surfaces both sample-level and function-group-level coverage.
  * ``cost_report.json`` — total executions, wall-clock seconds, repair model
    invocations, and tokens used.
  * ``failure_catalog.md`` — per-sample failure listing. Failures, abstentions
    and budget-exhausted samples are never deleted.
  * ``delivery_manifest.json`` — content-hash manifest of every artifact the
    delivery ships, plus the algorithm commitment and the selection manifest.

The generator is deterministic given the run directory; reruns produce the
same hashes. It does **not** lower Auditor thresholds or substitute proxy
signals for actual evidence.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .resolution import TERMINAL_STATUSES


SCHEMA_VERSION = "binoracle.phase4-delivery.v1"


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, ValueError):
        return []


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_json(value: Any) -> str:
    return _hash_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )


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


def _iter_sample_records(run_dir: Path) -> Iterable[dict[str, Any]]:
    """Walk a run directory and yield one record per Phase 4 sample."""

    for public_path in sorted((run_dir / "artifacts").rglob("binoracle_public_request.json")):
        artifact_dir = public_path.parent
        stage_dir = artifact_dir / "binoracle"
        public = _read_json(public_path, {})
        metadata = _read_json(artifact_dir / "binoracle_metadata.json", {})
        resolution = _read_json(stage_dir / "harness_resolution.json", {})
        capability = _read_json(stage_dir / "capability_reports.json", {})
        audit = _read_json(stage_dir / "audit_report.json", {})
        holdout_audit_paths = list(stage_dir.glob("contracts/*/holdout_audit.json"))
        holdout_audit = _read_json(holdout_audit_paths[0]) if holdout_audit_paths else None
        active_probe_paths = list(stage_dir.glob("contracts/*/active_probe_round-*.jsonl"))
        ambiguity = _read_json(stage_dir / "ambiguity_resolution.json")
        yield {
            "sample_id": public.get("sample_id") or metadata.get("sample_id"),
            "source_group_id": public.get("source_group_id")
            or metadata.get("source_group_id"),
            "optimization": public.get("optimization") or metadata.get("optimization"),
            "artifact_dir": str(artifact_dir.relative_to(run_dir)),
            "stage_dir": str(stage_dir.relative_to(run_dir)),
            "metadata": metadata,
            "resolution": resolution,
            "capability_reports": capability,
            "audit": audit,
            "holdout_audit": holdout_audit,
            "active_probe_round_paths": [str(p.relative_to(run_dir)) for p in active_probe_paths],
            "ambiguity_resolution": ambiguity,
        }


def _collect_transitions(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reconstruct observed (status, next_status) transitions per sample.

    The engine writes the terminal ``harness_resolution.json`` rather than a
    transition trace. We derive the implicit transitions from the public
    resolution model: INITIAL -> STATIC_INFERRED -> CAPABILITY_CHECKED ->
    PROBED -> {terminal}. Active-probe and ambiguity paths are reconstructed
    from the audit/active-probe artifacts so the matrix still reflects what
    actually happened instead of a fixed skeleton.
    """

    pairs: Counter[tuple[str, str]] = Counter()
    for record in records:
        resolution = record.get("resolution") or {}
        status = str(resolution.get("status") or "initial")
        audit = record.get("audit") or {}
        audit_decision = str(audit.get("decision") or "")
        holdout_audit = record.get("holdout_audit") or {}
        holdout_decision = str(holdout_audit.get("decision") or "")
        has_active_probes = bool(record.get("active_probe_round_paths"))
        ambiguity = record.get("ambiguity_resolution") or {}
        ambiguity_status = str(ambiguity.get("status") or "")

        skeleton: list[str] = ["initial", "static_inferred", "capability_checked", "probed"]
        if audit_decision == "ambiguous":
            skeleton.append("ambiguous")
            if ambiguity_status == "discriminated":
                skeleton.append("probed")
                if holdout_decision == "accepted":
                    skeleton.append("frozen")
                else:
                    skeleton.append("retryable_rejected")
            else:
                skeleton.append(status if status != "probed" else "behavioral_equivalence_class")
        elif audit_decision == "accepted":
            if holdout_decision == "accepted":
                skeleton.append("frozen")
            elif holdout_decision:
                skeleton.append("retryable_rejected")
                skeleton.append(status if status in {"unverified", "budget_exhausted"} else "unverified")
            else:
                skeleton.append("frozen")
        elif audit_decision == "rejected":
            skeleton.append("retryable_rejected")
            if has_active_probes:
                skeleton.append("probed")
            skeleton.append(status if status in {"frozen", "unverified", "budget_exhausted"} else "unverified")
        else:
            skeleton.append(status)
        # Always end on the actual recorded terminal state.
        if skeleton[-1] != status:
            skeleton.append(status)
        for source, target in zip(skeleton, skeleton[1:]):
            pairs[(source, target)] += 1
    return [
        {"source_status": source, "target_status": target, "count": count}
        for (source, target), count in sorted(pairs.items())
    ]


def _stratified_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute layered metrics with 95% Wilson confidence intervals.

    Denominators are fixed at the selection size: every sample in the run
    contributes regardless of whether its harness froze. This is the
    ``fixed_denominator`` policy mandated by section 12 of the plan.
    """

    def summarize(values: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(values)
        resolution_statuses = Counter(
            str((value.get("resolution") or {}).get("status") or "unknown")
            for value in values
        )
        terminal = sum(
            count
            for status, count in resolution_statuses.items()
            if status in {s.value for s in TERMINAL_STATUSES}
        )
        frozen = sum(1 for value in values if (value.get("metadata") or {}).get("harness_frozen"))
        behaviorally_equivalent = resolution_statuses.get("behavioral_equivalence_class", 0)
        unidentifiable = resolution_statuses.get("unidentifiable_from_binary", 0)
        unverified = resolution_statuses.get("unverified", 0)
        budget = resolution_statuses.get("budget_exhausted", 0)
        executions = sum(int((value.get("metadata") or {}).get("executions", 0)) for value in values)
        elapsed = sum(
            float((value.get("metadata") or {}).get("elapsed_seconds", 0.0))
            for value in values
        )
        return {
            "total": total,
            "terminal_state_count": terminal,
            "terminal_state_rate": terminal / total if total else None,
            "frozen_harnesses": frozen,
            "harness_freeze_rate_fixed_denominator": frozen / total if total else None,
            "harness_freeze_rate_fixed_denominator_ci95": _wilson_95(frozen, total),
            "behavioral_equivalence_class_count": behaviorally_equivalent,
            "unidentifiable_from_binary_count": unidentifiable,
            "unverified_count": unverified,
            "budget_exhausted_count": budget,
            "resolution_status_counts": dict(sorted(resolution_statuses.items())),
            "executions_total": executions,
            "wall_seconds_total": elapsed,
        }

    overall = summarize(records)
    by_optimization: dict[str, Any] = {}
    for optimization in sorted({str(value.get("optimization")) for value in records}):
        by_optimization[optimization] = summarize(
            [value for value in records if str(value.get("optimization")) == optimization]
        )
    by_group: dict[str, Any] = {}
    for group in sorted({str(value.get("source_group_id")) for value in records}):
        by_group[group] = summarize(
            [value for value in records if str(value.get("source_group_id")) == group]
        )
    return {
        "denominator_policy": "fixed: every sample in the committed selection",
        "overall": overall,
        "by_optimization": by_optimization,
        "by_source_group": by_group,
    }


def _cost_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    executions = sum(int((value.get("metadata") or {}).get("executions", 0)) for value in records)
    wall_seconds = sum(
        float((value.get("metadata") or {}).get("elapsed_seconds", 0.0)) for value in records
    )
    repair_iterations = sum(
        int((value.get("metadata") or {}).get("repair_iterations", 0)) for value in records
    )
    repair_model_calls = sum(
        int((value.get("metadata") or {}).get("repair_model_call_count", 0)) for value in records
    )
    repair_tokens = sum(
        int((value.get("metadata") or {}).get("repair_tokens_used", 0)) for value in records
    )
    return {
        "schema_version": "binoracle.phase4-cost.v1",
        "executions_total": executions,
        "wall_seconds_total": wall_seconds,
        "repair_iterations_total": repair_iterations,
        "repair_model_call_total": repair_model_calls,
        "repair_token_total": repair_tokens,
        "active_probe_rounds_total": sum(
            len(value.get("active_probe_round_paths") or []) for value in records
        ),
        "per_sample_mean_executions": executions / len(records) if records else None,
        "per_sample_mean_wall_seconds": wall_seconds / len(records) if records else None,
    }


def _failure_catalog(records: list[dict[str, Any]]) -> str:
    """Render a Markdown catalog of non-frozen / non-equivalent outcomes.

    Failures are never deleted: every non-frozen sample is listed with its
    resolution status, reasons, and pointers to the underlying artifacts so a
    reviewer can audit the algorithm's decision boundary.
    """

    lines: list[str] = [
        "# BinOracle Phase 4 Failure Catalog",
        "",
        "Every sample that did not reach `frozen` or a behavioural-equivalence",
        "terminal state is listed here. Per the Phase 4 plan, failures,",
        "abstentions and budget-exhausted samples are retained for audit and",
        "are not pruned to flatter coverage.",
        "",
    ]
    failures = []
    for value in records:
        metadata = value.get("metadata") or {}
        resolution = value.get("resolution") or {}
        status = str(resolution.get("status") or "unknown")
        if metadata.get("harness_frozen"):
            continue
        if status == "behavioral_equivalence_class":
            continue
        failures.append(value)
    if not failures:
        lines.extend(
            [
                "## No failures recorded",
                "",
                "Every sample in this run either froze its harness or landed in",
                "a behavioural-equivalence-class terminal state.",
                "",
            ]
        )
        return "\n".join(lines)
    failures.sort(key=lambda value: str(value.get("sample_id")))
    lines.extend(
        [
            f"## Total non-frozen samples: {len(failures)}",
            "",
            "| sample_id | optimization | resolution status | reasons | stop_reason |",
            "|---|---|---|---|---|",
        ]
    )
    for value in failures:
        metadata = value.get("metadata") or {}
        resolution = value.get("resolution") or {}
        status = str(resolution.get("status") or "unknown")
        reasons = ", ".join(resolution.get("reasons") or []) or "—"
        stop_reason = str(metadata.get("stop_reason") or "—")
        sample_id = str(value.get("sample_id") or "—")
        optimization = str(value.get("optimization") or "—")
        lines.append(
            f"| {sample_id} | {optimization} | {status} | {reasons} | {stop_reason} |"
        )
    lines.extend(
        [
            "",
            "## Representative artifacts",
            "",
            "Each entry above corresponds to a `binoracle_metadata.json` and a",
            "`harness_resolution.json` artifact under the sample's stage directory.",
            "Reviewer instructions: open the listed stage_dir to inspect the",
            "capability report, audit decisions, active-probe rounds, and any",
            "ambiguity-resolution record that justified the terminal state.",
            "",
        ]
    )
    return "\n".join(lines)


def _artifact_inventory(run_dir: Path) -> list[dict[str, Any]]:
    """Hash every artifact the delivery ships.

    Includes the algorithm commitment, selection manifest, capability report,
    sample artifacts, and the generated reports themselves (so the manifest
    is reproducible).
    """

    inventory: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"delivery_manifest.json"}:
            # The manifest itself is hashed separately to avoid a cycle.
            continue
        relative = path.relative_to(run_dir)
        inventory.append(
            {
                "relative_path": str(relative),
                "size_bytes": path.stat().st_size,
                "sha256": _hash_bytes(path.read_bytes()),
            }
        )
    return inventory


def build_delivery_manifest(
    run_dir: Path,
    *,
    experiment: str,
    algorithm_commitment: dict[str, Any],
    selection_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce every §17 deliverable (6 + 8) for a Phase 4 run.

    The run directory layout is expected to follow the recommended layout in
    section 17 of the plan: ``runs/binoracle-phase4-<experiment>/artifacts/...
    /binoracle_public_request.json``. This function is idempotent: reruns
    reproduce the same hashes.
    """

    run_dir = run_dir.resolve()
    reports_dir = run_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    records = list(_iter_sample_records(run_dir))
    records.sort(key=lambda value: str(value.get("sample_id")))

    transitions = _collect_transitions(records)
    with (reports_dir / "state_transition_matrix.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["source_status", "target_status", "count"]
        )
        writer.writeheader()
        for row in transitions:
            writer.writerow(row)

    stratified = _stratified_metrics(records)
    (reports_dir / "stratified_metrics.json").write_text(
        json.dumps(stratified, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Layered CSV the plan explicitly asks for.
    with (reports_dir / "group_level_coverage.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        fieldnames = [
            "stratum",
            "total",
            "frozen_harnesses",
            "harness_freeze_rate_fixed_denominator",
            "harness_freeze_rate_fixed_denominator_ci95_low",
            "harness_freeze_rate_fixed_denominator_ci95_high",
            "terminal_state_count",
            "executions_total",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for stratum_name in ("overall",):
            row = {"stratum": stratum_name, **stratified[stratum_name]}
            ci = stratified[stratum_name].get("harness_freeze_rate_fixed_denominator_ci95")
            if ci and len(ci) == 2:
                row["harness_freeze_rate_fixed_denominator_ci95_low"] = ci[0]
                row["harness_freeze_rate_fixed_denominator_ci95_high"] = ci[1]
            writer.writerow(row)
        for optimization, value in stratified["by_optimization"].items():
            row = {"stratum": "optimization=" + optimization, **value}
            ci = value.get("harness_freeze_rate_fixed_denominator_ci95")
            if ci and len(ci) == 2:
                row["harness_freeze_rate_fixed_denominator_ci95_low"] = ci[0]
                row["harness_freeze_rate_fixed_denominator_ci95_high"] = ci[1]
            writer.writerow(row)
        for group, value in stratified["by_source_group"].items():
            row = {"stratum": "source_group=" + group, **value}
            ci = value.get("harness_freeze_rate_fixed_denominator_ci95")
            if ci and len(ci) == 2:
                row["harness_freeze_rate_fixed_denominator_ci95_low"] = ci[0]
                row["harness_freeze_rate_fixed_denominator_ci95_high"] = ci[1]
            writer.writerow(row)

    cost = _cost_report(records)
    (reports_dir / "cost_report.json").write_text(
        json.dumps(cost, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    failure_catalog = _failure_catalog(records)
    (reports_dir / "failure_catalog.md").write_text(failure_catalog, encoding="utf-8")

    # Persist the per-sample record set so reviewers can audit every status.
    (reports_dir / "phase4_sample_records.jsonl").write_text(
        "".join(
            json.dumps(
                {
                    "sample_id": value.get("sample_id"),
                    "source_group_id": value.get("source_group_id"),
                    "optimization": value.get("optimization"),
                    "artifact_dir": value.get("artifact_dir"),
                    "stage_dir": value.get("stage_dir"),
                    "resolution": value.get("resolution"),
                    "harness_frozen": bool((value.get("metadata") or {}).get("harness_frozen")),
                    "executions": int((value.get("metadata") or {}).get("executions", 0)),
                    "stop_reason": (value.get("metadata") or {}).get("stop_reason"),
                    "active_probe_rounds": value.get("active_probe_round_paths") or [],
                    "ambiguity_resolution": value.get("ambiguity_resolution"),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
            for value in records
        ),
        encoding="utf-8",
    )

    inventory = _artifact_inventory(run_dir)
    core = {
        "schema_version": SCHEMA_VERSION,
        "experiment": experiment,
        "run_dir": str(run_dir),
        "algorithm_commitment": algorithm_commitment,
        "selection_manifest": selection_manifest,
        "sample_count": len(records),
        "artifact_inventory": inventory,
    }
    manifest = {**core, "content_hash": _hash_json(core)}
    (run_dir / "delivery_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


__all__ = ["build_delivery_manifest"]
