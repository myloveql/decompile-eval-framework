from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from typing import Any, Iterable

from decomp_eval.selection import SELECTION_MANIFEST_SCHEMA
from decomp_eval.util import sha256_json

from .contract import infer_contract


REQUIRED_OPTIMIZATIONS = ("O0", "O1", "O2", "O3")


def _stable_rank(seed: int, source_group_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{source_group_id}".encode("utf-8")).hexdigest()


def _public_stratum(rows: list[dict[str, Any]], *, assembly_view: str) -> tuple[int, int]:
    """Classify using assembly only; source signatures and tests are never read."""

    max_arguments = 0
    has_pointer = False
    for row in rows:
        assembly = str((row.get("assembly") or {}).get(assembly_view, ""))
        contract = infer_contract(assembly)
        max_arguments = max(max_arguments, len(contract.arguments))
        has_pointer = has_pointer or any(
            item.kind_candidates[0] == "pointer" for item in contract.arguments
        )
    return int(has_pointer), min(max_arguments, 3)


def build_group_selection_manifest(
    rows: Iterable[dict[str, Any]],
    *,
    dataset_id: str,
    split: str,
    group_count: int,
    seed: int,
    assembly_view: str = "objdump_att_instruction_only",
) -> dict[str, Any]:
    """Select complete O0-O3 source groups with deterministic stratum round-robin."""

    if group_count <= 0:
        raise ValueError("group_count must be positive")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["source_group_id"])].append(row)

    eligible: list[tuple[str, list[dict[str, Any]]]] = []
    exclusions: list[dict[str, Any]] = []
    for group_id in sorted(grouped):
        group_rows = grouped[group_id]
        by_opt = {str(row["optimization"]): row for row in group_rows}
        missing = [opt for opt in REQUIRED_OPTIMIZATIONS if opt not in by_opt]
        duplicate = len(by_opt) != len(group_rows)
        missing_public_input = any(
            not str((row.get("assembly") or {}).get(assembly_view, "")).strip()
            or not str((row.get("binary") or {}).get("path", "")).strip()
            for row in group_rows
        )
        reasons = []
        if missing:
            reasons.append("missing_optimizations:" + ",".join(missing))
        if duplicate:
            reasons.append("duplicate_optimization")
        if missing_public_input:
            reasons.append("missing_binary_or_assembly")
        if reasons:
            exclusions.append({"source_group_id": group_id, "reasons": reasons})
            continue
        eligible.append((group_id, [by_opt[opt] for opt in REQUIRED_OPTIMIZATIONS]))

    if len(eligible) < group_count:
        raise ValueError(
            f"requested {group_count} complete groups, only {len(eligible)} are eligible"
        )

    buckets: dict[
        tuple[int, int], list[tuple[str, list[dict[str, Any]]]]
    ] = defaultdict(list)
    for group_id, group_rows in eligible:
        buckets[_public_stratum(group_rows, assembly_view=assembly_view)].append(
            (group_id, group_rows)
        )
    queues = {
        stratum: deque(sorted(values, key=lambda item: _stable_rank(seed, item[0])))
        for stratum, values in buckets.items()
    }
    selected: list[tuple[str, list[dict[str, Any]]]] = []
    strata = sorted(queues)
    while len(selected) < group_count:
        progressed = False
        for stratum in strata:
            if queues[stratum] and len(selected) < group_count:
                selected.append(queues[stratum].popleft())
                progressed = True
        if not progressed:
            raise RuntimeError("selection queues were exhausted unexpectedly")

    entries = []
    stratum_counts: dict[str, int] = defaultdict(int)
    for group_id, group_rows in selected:
        stratum = _public_stratum(group_rows, assembly_view=assembly_view)
        stratum_counts[f"pointer={stratum[0]},max_args={stratum[1]}"] += 1
        for row in group_rows:
            entries.append(
                {
                    "dataset_id": dataset_id,
                    "split": split,
                    "sample_id": str(row["sample_id"]),
                    "source_group_id": group_id,
                    "optimization": str(row["optimization"]),
                    "content_hash": sha256_json(row),
                }
            )

    return {
        "schema": SELECTION_MANIFEST_SCHEMA,
        "selection_hash": sha256_json(entries),
        "sample_count": len(entries),
        "entries": entries,
        "binoracle_selection": {
            "schema": "binoracle.phase2-selection/v1",
            "seed": seed,
            "group_count": group_count,
            "required_optimizations": list(REQUIRED_OPTIMIZATIONS),
            "assembly_view": assembly_view,
            "selection_policy": "complete_source_groups_stratified_by_public_assembly",
            "stratum_group_counts": dict(sorted(stratum_counts.items())),
            "eligible_group_count": len(eligible),
            "excluded_group_count": len(exclusions),
            "excluded_groups": exclusions,
        },
    }
