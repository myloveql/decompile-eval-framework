from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from .protocol import InputCase, KnownContract
from .probes import ProbeCase


@dataclass(frozen=True)
class MinimizationAttempt:
    transformation: str
    kept: bool
    input_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "transformation": self.transformation,
            "kept": self.kept,
            "input_hash": self.input_hash,
        }


@dataclass(frozen=True)
class MinimizationResult:
    original_probe_id: str
    input_case: InputCase
    attempts: tuple[MinimizationAttempt, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.minimized-input.v1",
            "original_probe_id": self.original_probe_id,
            "input_case": self.input_case.to_dict(),
            "attempts": [item.to_dict() for item in self.attempts],
        }


def _input_hash(value: InputCase) -> str:
    encoded = json.dumps(
        value.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _replace_input(
    current: InputCase,
    *,
    contract: KnownContract,
    gpr: dict[str, Any] | None = None,
    objects: dict[str, dict[str, Any]] | None = None,
) -> InputCase:
    value = current.to_dict()
    if gpr is not None:
        value["gpr"] = gpr
    if objects is not None:
        value["objects"] = objects
    return InputCase.from_dict(value, contract=contract)


def minimize_counterexample(
    probe: ProbeCase,
    *,
    contract: KnownContract,
    is_counterexample: Callable[[InputCase], bool],
    max_attempts: int = 8,
) -> MinimizationResult:
    """Greedily remove irrelevant input complexity without changing frozen tests.

    The returned input is diagnostic evidence only. It is never inserted into the
    frozen Harness manifest and therefore cannot change pass/fail retroactively.
    """

    current = probe.input_case
    attempts: list[MinimizationAttempt] = []

    def attempt(name: str, candidate: InputCase) -> None:
        nonlocal current
        if len(attempts) >= max_attempts or candidate == current:
            return
        kept = bool(is_counterexample(candidate))
        attempts.append(MinimizationAttempt(name, kept, _input_hash(candidate)))
        if kept:
            current = candidate

    for slot in sorted(current.gpr):
        value = current.gpr[slot]
        if isinstance(value, int) and not isinstance(value, bool) and value != 0:
            gpr = dict(current.gpr)
            gpr[slot] = 0
            attempt(f"zero_integer:{slot}", _replace_input(current, contract=contract, gpr=gpr))

    object_specs = {
        str(item["object_id"]): int(item.get("min_size", 1))
        for item in contract.objects
    }
    for object_id in sorted(current.objects):
        item = dict(current.objects[object_id])
        size = int(item["size"])
        if any(bytes.fromhex(str(item["bytes_hex"]))):
            objects = {key: dict(value) for key, value in current.objects.items()}
            objects[object_id]["bytes_hex"] = bytes(size).hex()
            attempt(
                f"zero_object:{object_id}",
                _replace_input(current, contract=contract, objects=objects),
            )
        minimum = object_specs.get(object_id, size)
        current_item = current.objects[object_id]
        if int(current_item["size"]) > minimum:
            objects = {key: dict(value) for key, value in current.objects.items()}
            raw = bytes.fromhex(str(objects[object_id]["bytes_hex"]))[:minimum]
            objects[object_id]["size"] = minimum
            objects[object_id]["bytes_hex"] = raw.hex()
            attempt(
                f"shrink_object:{object_id}",
                _replace_input(current, contract=contract, objects=objects),
            )
        if current.objects[object_id].get("placement") != "right":
            objects = {key: dict(value) for key, value in current.objects.items()}
            objects[object_id]["placement"] = "right"
            attempt(
                f"normalize_placement:{object_id}",
                _replace_input(current, contract=contract, objects=objects),
            )
    return MinimizationResult(probe.probe_id, current, tuple(attempts))


def build_evidence_package(
    *,
    sample_id: str,
    contract_hash: str,
    harness_hash: str,
    probe: ProbeCase,
    original: dict[str, Any],
    candidate: dict[str, Any],
    difference: dict[str, Any],
    minimized: MinimizationResult | None = None,
) -> dict[str, Any]:
    identity = {
        "sample_id": sample_id,
        "contract_hash": contract_hash,
        "harness_hash": harness_hash,
        "probe_id": probe.probe_id,
        "difference_kinds": difference.get("kinds", []),
    }
    evidence_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "binoracle.evidence.v1",
        "evidence_id": evidence_id,
        **identity,
        "input": probe.input_case.to_dict(),
        "minimized_input": minimized.to_dict() if minimized else None,
        "original_observation": original,
        "candidate_observation": candidate,
        "difference": difference,
        "localization": {
            "status": "not_implemented",
            "original_pc": None,
            "candidate_source_location": None,
        },
        "harness_mutated": False,
    }
