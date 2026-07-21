from __future__ import annotations

import itertools
from typing import Any, Iterable

from .contract_v2 import ContractGraphV2, MAX_OBJECT_BYTES, SCHEMA_VERSION
from .taint import SUPPORTED_ARGUMENT_REGISTERS, TaintAnalysis


def _kind_options(analysis: TaintAnalysis, register: str) -> tuple[tuple[str, float], ...]:
    if register in analysis.pointer_evidence:
        return (("pointer", 0.90), ("integer", 0.25))
    return (("integer", 0.65), ("pointer", 0.20))


def _return_options(analysis: TaintAnalysis) -> tuple[tuple[str, float], ...]:
    pointer_origins = {
        f"arg:{register}" for register in analysis.pointer_evidence
    }
    if pointer_origins.intersection(analysis.return_taint) or any(
        value.startswith("symbol:") for value in analysis.return_taint
    ):
        return (
            ("object_pointer", 0.75),
            ("void", 0.55),
            ("integer", 0.45),
        )
    has_definition = any(
        "rax_defined_before_return" in item for item in analysis.return_evidence
    )
    if has_definition:
        return (("integer", 0.55), ("void", 0.45))
    return (("void", 0.70),)


def _object_payload(
    analysis: TaintAnalysis, register: str, object_id: str
) -> tuple[dict[str, Any], list[str]]:
    accesses = analysis.pointer_evidence.get(register, ())
    unsupported: list[str] = []
    reads: set[tuple[int, int]] = set()
    writes: set[tuple[int, int]] = set()
    evidence_ids: list[str] = []
    maximum = 1
    for access in accesses:
        evidence_ids.append(access.instruction_id)
        if access.displacement is None or access.displacement < 0:
            unsupported.append(
                f"unknown_or_negative_object_range:{register}:{access.instruction_id}"
            )
            continue
        end = access.displacement + access.width
        if end > MAX_OBJECT_BYTES:
            unsupported.append(
                f"object_exceeds_max_bytes:{register}:{end}"
            )
            end = MAX_OBJECT_BYTES
        if access.displacement >= end:
            continue
        maximum = max(maximum, end)
        item = (access.displacement, end)
        if access.direction in {"read", "read_write"}:
            reads.add(item)
        if access.direction in {"write", "read_write"}:
            writes.add(item)
    if not accesses:
        evidence_ids.append(f"hypothesis:{register}:pointer_without_memory_access")
    return (
        {
            "object_id": object_id,
            "argument_slot": register,
            "min_size": maximum,
            "alignment": 1,
            "read_ranges": [list(item) for item in sorted(reads)],
            "write_ranges": [list(item) for item in sorted(writes)],
            "evidence_ids": sorted(set(evidence_ids)),
        },
        unsupported,
    )


def generate_contract_candidates(
    analysis: TaintAnalysis,
    *,
    sample_id: str,
    abi: str,
    globals: Iterable[dict[str, Any]] = (),
    dependencies: Iterable[dict[str, Any]] = (),
    max_candidates: int = 4,
) -> tuple[ContractGraphV2, ...]:
    if max_candidates <= 0:
        raise ValueError("max_candidates must be positive")
    observed_indices = [
        index
        for index, register in enumerate(SUPPORTED_ARGUMENT_REGISTERS)
        if register in analysis.argument_evidence
    ]
    observed = list(
        SUPPORTED_ARGUMENT_REGISTERS[: max(observed_indices) + 1]
        if observed_indices
        else ()
    )
    unsupported_registers = sorted(
        set(analysis.argument_evidence) - set(SUPPORTED_ARGUMENT_REGISTERS)
    )
    argument_options = [_kind_options(analysis, register) for register in observed]
    combinations = itertools.product(*argument_options) if argument_options else [()]
    ranked: list[tuple[float, tuple[str, ...], str, dict[str, Any]]] = []
    for kinds_with_scores in combinations:
        kinds = tuple(item[0] for item in kinds_with_scores)
        kind_scores = [item[1] for item in kinds_with_scores]
        for return_kind, return_score in _return_options(analysis):
            arguments = []
            objects = []
            unsupported = []
            if unsupported_registers:
                unsupported.append(
                    "unsupported_argument_slots:" + ",".join(unsupported_registers)
                )
            evidence_ids: list[str] = []
            for slot, (register, kind) in enumerate(zip(observed, kinds)):
                register_evidence = list(
                    analysis.argument_evidence.get(
                        register, (f"abi_prefix_required:{register}",)
                    )
                )
                evidence_ids.extend(register_evidence)
                argument: dict[str, Any] = {
                    "slot": slot,
                    "register": register,
                    "kind_candidates": [kind, "integer" if kind == "pointer" else "pointer"],
                    "confidence": dict(_kind_options(analysis, register))[kind],
                    "evidence_ids": register_evidence,
                }
                if kind == "pointer":
                    object_id = f"obj{len(objects)}"
                    argument["object_ref"] = object_id
                    object_value, object_unsupported = _object_payload(
                        analysis, register, object_id
                    )
                    objects.append(object_value)
                    unsupported.extend(object_unsupported)
                arguments.append(argument)
            score_parts = kind_scores + [return_score]
            score = sum(score_parts) / len(score_parts)
            payload = {
                "schema_version": SCHEMA_VERSION,
                "sample_id": sample_id,
                "contract_id": "pending",
                "abi": abi,
                "arguments": arguments,
                "objects": objects,
                "return": {
                    "kind_candidates": [
                        return_kind,
                        *(["void"] if return_kind == "integer" else []),
                    ],
                    "confidence": return_score,
                    "observable": return_kind == "integer",
                    "evidence_ids": list(analysis.return_evidence),
                },
                "relations": [],
                "globals": [dict(item) for item in globals],
                "dependencies": [dict(item) for item in dependencies],
                "unsupported_reasons": sorted(set(unsupported)),
                "confidence": score,
                "evidence_ids": sorted(set(evidence_ids)),
            }
            ranked.append((score, kinds, return_kind, payload))
    ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
    result = []
    for index, (_, _, _, payload) in enumerate(ranked[:max_candidates]):
        payload["contract_id"] = f"K_static_{index}"
        result.append(ContractGraphV2.from_dict(payload))
    return tuple(result)
