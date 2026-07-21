from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .auditor import verify_harness_manifest


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _kind(type_name: str, *, is_return: bool = False) -> str:
    normalized = " ".join(type_name.replace("\t", " ").split()).lower()
    if normalized == "void":
        return "void"
    if "*" in normalized or "[" in normalized:
        return "object_pointer" if is_return else "pointer"
    if any(token in normalized for token in ("float", "double", "__m128", "__m256")):
        return "unsupported_float"
    if any(token in normalized for token in ("struct ", "union ", "class ")):
        return "unsupported_aggregate"
    return "integer"


def _truth_contract(sample: dict[str, Any]) -> dict[str, Any] | None:
    source = sample.get("source")
    if not isinstance(source, dict):
        return None
    signature = source.get("signature")
    if not isinstance(signature, list) or not signature:
        return None
    arguments = [_kind(str(value)) for value in signature[1:]]
    return_kind = _kind(str(signature[0]), is_return=True)
    reasons: list[str] = []
    if len(arguments) > 3:
        reasons.append("more_than_three_arguments")
    if sum(value == "pointer" for value in arguments) > 1:
        reasons.append("multiple_independent_pointer_objects")
    if any(value.startswith("unsupported_") for value in arguments):
        reasons.append("unsupported_argument_abi_class")
    if return_kind.startswith("unsupported_"):
        reasons.append("unsupported_return_abi_class")
    return {
        "argument_kinds": arguments,
        "return_kind": return_kind,
        "supported_by_runner_v1": not reasons,
        "unsupported_reasons": reasons,
    }


def _candidate_matches(candidate: dict[str, Any], truth: dict[str, Any]) -> bool:
    return _candidate_arguments_match(candidate, truth) and _candidate_return_kind(
        candidate
    ) == truth["return_kind"]


def _candidate_argument_kinds(candidate: dict[str, Any]) -> list[str]:
    return [
        str(item.get("kind_candidates", ["unknown"])[0])
        for item in candidate.get("arguments", [])
    ]


def _candidate_return_kind(candidate: dict[str, Any]) -> str:
    return str(
        candidate.get("return", {}).get("kind_candidates", ["unknown"])[0]
    )


def _candidate_arguments_match(candidate: dict[str, Any], truth: dict[str, Any]) -> bool:
    return _candidate_argument_kinds(candidate) == truth["argument_kinds"]


def _status(metadata: dict[str, Any]) -> tuple[str, str]:
    selection = str(metadata.get("contract_selection_status") or "")
    if selection == "audit_accepted_frozen":
        return "accepted", "complete"
    if selection == "audit_ambiguous":
        return "ambiguous", "contract_audit"
    if selection == "audit_rejected":
        return "rejected", "contract_audit"
    if selection == "dynamic_scored_unreviewed":
        return "unreviewed", "dynamic_scoring"
    reason = str(metadata.get("unsupported_reason") or metadata.get("stop_reason") or "unknown")
    if "no_runnable_candidate" in reason:
        return "unsupported", "runner_boundary"
    if reason.startswith("binoracle_unsupported") or reason.startswith("unsupported_"):
        return "unsupported", reason
    return "failed", reason


def _score_for(
    scores: Iterable[dict[str, Any]], contract_id: str | None
) -> dict[str, Any] | None:
    if not contract_id:
        return None
    return next((value for value in scores if value.get("contract_id") == contract_id), None)


def _safe_ratio(numerator: int | float, denominator: int | float) -> float | None:
    return float(numerator) / float(denominator) if denominator else None


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(str(value["status"]) for value in records)
    truth_records = [value for value in records if value.get("truth") is not None]
    supported = [
        value for value in truth_records if value["truth"]["supported_by_runner_v1"]
    ]
    identifiable = [
        value for value in supported if value.get("truth_identifiable_from_binary")
    ]
    accepted = [value for value in records if value["status"] == "accepted"]
    source_top1_hits = sum(bool(value.get("top1_truth_match")) for value in supported)
    source_topk_hits = sum(bool(value.get("topk_truth_match")) for value in supported)
    top1_hits = sum(bool(value.get("top1_truth_match")) for value in identifiable)
    topk_hits = sum(bool(value.get("topk_truth_match")) for value in identifiable)
    dynamic_top1_hits = sum(
        bool(value.get("dynamic_leading_truth_match")) for value in identifiable
    )
    random_expected_probabilities = [
        float(value["random_legal_expected_truth_match_probability"])
        for value in identifiable
        if value.get("random_legal_expected_truth_match_probability") is not None
    ]
    static_argument_hits = sum(
        bool(value.get("top1_argument_truth_match")) for value in identifiable
    )
    dynamic_argument_hits = sum(
        bool(value.get("dynamic_leading_argument_truth_match")) for value in identifiable
    )
    return_only_mismatches = sum(
        bool(value.get("dynamic_leading_argument_truth_match"))
        and not bool(value.get("dynamic_leading_truth_match"))
        for value in identifiable
    )
    return_ambiguous_mismatches = sum(
        bool(value.get("dynamic_return_ambiguous_with_truth")) for value in identifiable
    )

    tp = fp = fn = 0
    for value in identifiable:
        truth_args = value["truth"]["argument_kinds"]
        predicted_args = value.get("top1_argument_kinds", [])
        for index in range(max(len(truth_args), len(predicted_args))):
            expected = truth_args[index] if index < len(truth_args) else "missing"
            predicted = predicted_args[index] if index < len(predicted_args) else "missing"
            tp += expected == "pointer" and predicted == "pointer"
            fp += expected != "pointer" and predicted == "pointer"
            fn += expected == "pointer" and predicted != "pointer"
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    pointer_f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    valid_rates = [
        float(value["accepted_valid_call_rate"])
        for value in accepted
        if value.get("accepted_valid_call_rate") is not None
    ]
    frozen_verified = sum(bool(value.get("frozen_manifest_verified")) for value in accepted)
    return {
        "total": len(records),
        "status_counts": dict(sorted(statuses.items())),
        "accepted_rate": _safe_ratio(len(accepted), len(records)),
        "truth_available": len(truth_records),
        "runner_v1_truth_supported": len(supported),
        "binary_identifiable_runner_v1_truth_supported": len(identifiable),
        "source_signature_top1_rate": _safe_ratio(source_top1_hits, len(supported)),
        "source_signature_topk_rate": _safe_ratio(source_topk_hits, len(supported)),
        "complete_contract_top1_hits": top1_hits,
        "complete_contract_top1_rate": _safe_ratio(top1_hits, len(identifiable)),
        "complete_contract_topk_hits": topk_hits,
        "complete_contract_topk_rate": _safe_ratio(topk_hits, len(identifiable)),
        "dynamic_leading_top1_hits": dynamic_top1_hits,
        "dynamic_leading_top1_rate": _safe_ratio(dynamic_top1_hits, len(identifiable)),
        "random_legal_expected_top1_rate": (
            sum(random_expected_probabilities) / len(random_expected_probabilities)
            if random_expected_probabilities
            else None
        ),
        "static_argument_top1_hits": static_argument_hits,
        "static_argument_top1_rate": _safe_ratio(static_argument_hits, len(identifiable)),
        "dynamic_argument_top1_hits": dynamic_argument_hits,
        "dynamic_argument_top1_rate": _safe_ratio(dynamic_argument_hits, len(identifiable)),
        "dynamic_return_only_mismatches": return_only_mismatches,
        "dynamic_return_ambiguous_with_truth": return_ambiguous_mismatches,
        "pointer_precision": precision,
        "pointer_recall": recall,
        "pointer_f1": pointer_f1,
        "accepted_valid_call_rate_mean": (
            sum(valid_rates) / len(valid_rates) if valid_rates else None
        ),
        "accepted_frozen_manifests_verified": frozen_verified,
        "accepted_frozen_manifest_integrity_rate": _safe_ratio(frozen_verified, len(accepted)),
        "executions": sum(int(value.get("executions", 0)) for value in records),
        "failure_stage_counts": dict(
            sorted(Counter(str(value["failure_stage"]) for value in records).items())
        ),
    }


def summarize_phase2_run(
    run_dir: Path,
    *,
    dataset_path: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    output_dir = (output_dir or (run_dir / "binoracle_phase2")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_by_id: dict[str, dict[str, Any]] = {}
    dataset_sha256 = None
    if dataset_path is not None:
        dataset_path = dataset_path.resolve()
        raw_dataset = dataset_path.read_bytes()
        dataset_sha256 = hashlib.sha256(raw_dataset).hexdigest()
        dataset = json.loads(raw_dataset)
        dataset_by_id = {
            str(value["sample_id"]): value for value in dataset.get("samples", [])
        }

    records: list[dict[str, Any]] = []
    for public_path in sorted((run_dir / "artifacts").rglob("binoracle_public_request.json")):
        artifact_dir = public_path.parent
        public = _read_json(public_path, {})
        metadata = _read_json(artifact_dir / "binoracle_metadata.json", {})
        stage_dir = artifact_dir / "binoracle"
        candidates = _read_json(stage_dir / "contract_candidates.json", [])
        scores = _read_json(stage_dir / "contract_scores.json", [])
        taint_analysis = _read_json(stage_dir / "taint_analysis.json", {})
        audit = _read_json(stage_dir / "audit_report.json", {})
        status, failure_stage = _status(metadata)
        sample_id = str(public.get("sample_id") or metadata.get("sample_id") or artifact_dir.name)
        selected_id = metadata.get("selected_contract") or audit.get("selected_contract")
        leading_id = metadata.get("leading_contract")
        selected_score = _score_for(scores, str(selected_id) if selected_id else None)
        leading_score = _score_for(scores, str(leading_id) if leading_id else None)
        top1 = candidates[0] if candidates else None
        leading_candidate = next(
            (candidate for candidate in candidates if candidate.get("contract_id") == leading_id),
            None,
        )
        truth = _truth_contract(dataset_by_id[sample_id]) if sample_id in dataset_by_id else None
        leading_argument_kinds = (
            _candidate_argument_kinds(leading_candidate)
            if leading_candidate is not None
            else []
        )
        leading_return_hypotheses = sorted(
            {
                _candidate_return_kind(candidate)
                for candidate in candidates
                if _candidate_argument_kinds(candidate) == leading_argument_kinds
            }
        )
        public_boundary_reasons = sorted(
            {
                f"unsupported_dependency:{dependency.get('name')}"
                for candidate in candidates
                for dependency in candidate.get("dependencies", [])
                if dependency.get("direct_from_target") and not dependency.get("supported")
            }
        )
        if truth is not None and public_boundary_reasons:
            truth = {
                **truth,
                "supported_by_runner_v1": False,
                "unsupported_reasons": sorted(
                    set(truth["unsupported_reasons"]) | set(public_boundary_reasons)
                ),
            }
        identifiable = False
        if truth is not None and top1 is not None:
            top1_arguments = top1.get("arguments", [])
            pointer_evidence = taint_analysis.get("pointer_evidence", {})
            identifiable = len(top1_arguments) == len(truth["argument_kinds"]) and all(
                (
                    argument.get("register") in pointer_evidence
                    if expected_kind == "pointer"
                    else any(
                        not str(evidence).startswith("abi_prefix_required:")
                        for evidence in argument.get("evidence_ids", [])
                    )
                )
                for argument, expected_kind in zip(
                    top1_arguments, truth["argument_kinds"]
                )
            )
        manifest_path = stage_dir / "harness_manifest.json"
        manifest = _read_json(manifest_path)
        record = {
            "schema_version": "binoracle.contract-result.v2",
            "sample_id": sample_id,
            "source_group_id": public.get("source_group_id") or metadata.get("source_group_id"),
            "function_name": public.get("function_name"),
            "optimization": public.get("optimization") or metadata.get("optimization"),
            "status": status,
            "failure_stage": failure_stage,
            "stop_reason": metadata.get("stop_reason"),
            "unsupported_reason": metadata.get("unsupported_reason"),
            "contract_candidates": len(candidates),
            "runnable_contracts": int(metadata.get("runnable_contracts", 0)),
            "selected_contract": selected_id,
            "leading_contract": leading_id,
            "executions": int(metadata.get("executions", 0)),
            "valid_original_executions": int(metadata.get("valid_original_executions", 0)),
            "accepted_valid_call_rate": (
                selected_score.get("components", {}).get("valid")
                if selected_score is not None
                else None
            ),
            "leading_valid_call_rate": (
                leading_score.get("components", {}).get("valid")
                if leading_score is not None
                else None
            ),
            "frozen_manifest_verified": (
                verify_harness_manifest(manifest) if manifest is not None else False
            ),
            "top1_argument_kinds": (
                _candidate_argument_kinds(top1)
                if top1 is not None
                else []
            ),
            "dynamic_leading_argument_kinds": leading_argument_kinds,
            "dynamic_leading_return_kind": (
                _candidate_return_kind(leading_candidate)
                if leading_candidate is not None
                else None
            ),
            "dynamic_leading_return_hypotheses": leading_return_hypotheses,
            "truth": truth,
            "truth_identifiable_from_binary": identifiable if truth is not None else None,
            "top1_truth_match": (
                _candidate_matches(top1, truth) if top1 is not None and truth is not None else None
            ),
            "top1_argument_truth_match": (
                _candidate_arguments_match(top1, truth)
                if top1 is not None and truth is not None
                else None
            ),
            "topk_truth_match": (
                any(_candidate_matches(candidate, truth) for candidate in candidates)
                if truth is not None
                else None
            ),
            "random_legal_expected_truth_match_probability": (
                sum(_candidate_matches(candidate, truth) for candidate in candidates)
                / len(candidates)
                if truth is not None and candidates
                else None
            ),
            "dynamic_leading_truth_match": (
                _candidate_matches(leading_candidate, truth)
                if leading_candidate is not None and truth is not None
                else None
            ),
            "dynamic_leading_argument_truth_match": (
                _candidate_arguments_match(leading_candidate, truth)
                if leading_candidate is not None and truth is not None
                else None
            ),
            "dynamic_return_ambiguous_with_truth": (
                _candidate_arguments_match(leading_candidate, truth)
                and not _candidate_matches(leading_candidate, truth)
                and truth["return_kind"] in leading_return_hypotheses
                and len(leading_return_hypotheses) > 1
                if leading_candidate is not None and truth is not None
                else None
            ),
        }
        records.append(record)

    by_optimization = {
        optimization: _summary(
            [value for value in records if str(value.get("optimization")) == optimization]
        )
        for optimization in sorted(
            {str(value.get("optimization")) for value in records}
        )
    }
    report = {
        "schema_version": "binoracle.contract-summary.v2",
        "run_dir": str(run_dir),
        "evaluation_scope": (
            "offline_private_truth" if dataset_path is not None else "public_artifacts_only"
        ),
        "dataset_path": str(dataset_path) if dataset_path is not None else None,
        "dataset_sha256": dataset_sha256,
        "truth_feedback_to_contract_recovery": False,
        "overall": _summary(records),
        "by_optimization": by_optimization,
    }
    report["method_comparison"] = {
        "evaluation_denominator": "binary_identifiable_runner_v1_truth_supported",
        "random_legal_contract_expected_top1": report["overall"][
            "random_legal_expected_top1_rate"
        ],
        "static_top1": report["overall"]["complete_contract_top1_rate"],
        "static_topk_oracle_coverage": report["overall"]["complete_contract_topk_rate"],
        "static_topk_plus_dynamic_leading": report["overall"][
            "dynamic_leading_top1_rate"
        ],
        "static_topk_plus_dynamic_argument_contract": report["overall"][
            "dynamic_argument_top1_rate"
        ],
    }

    results_path = output_dir / "contract_results.jsonl"
    results_path.write_text(
        "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in records),
        encoding="utf-8",
    )
    _write_json(output_dir / "contract_summary.json", report)
    with (output_dir / "contract_summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "optimization",
                "total",
                "accepted_rate",
                "runner_v1_truth_supported",
                "binary_identifiable_runner_v1_truth_supported",
                "source_signature_top1_rate",
                "source_signature_topk_rate",
                "complete_contract_top1_rate",
                "complete_contract_topk_rate",
                "dynamic_leading_top1_rate",
                "random_legal_expected_top1_rate",
                "static_argument_top1_rate",
                "dynamic_argument_top1_rate",
                "dynamic_return_only_mismatches",
                "dynamic_return_ambiguous_with_truth",
                "pointer_f1",
                "accepted_valid_call_rate_mean",
                "accepted_frozen_manifest_integrity_rate",
                "executions",
            ],
            extrasaction="ignore",
        )
        writer.writeheader()
        for optimization, value in ["overall", report["overall"]], *by_optimization.items():
            writer.writerow({"optimization": optimization, **value})
    return report


__all__ = ["summarize_phase2_run"]
