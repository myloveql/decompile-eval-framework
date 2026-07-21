from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .contract_v2 import ContractGraphV2, ContractValidationError
from .protocol import InputCase


INTEGER_PROBES = (0, 1, -1, -(2**31), 2**31 - 1)


def _seed(base_seed: int, contract_id: str, case_id: str) -> int:
    digest = hashlib.sha256(
        f"{base_seed}\0{contract_id}\0{case_id}".encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:4], "big") & 0x7FFFFFFF


def _pattern(size: int, kind: str) -> bytes:
    if kind == "zero":
        return bytes(size)
    if kind == "repeat_a5":
        return bytes([0xA5]) * size
    if kind == "pulse_start":
        return bytes([1]) + bytes(max(0, size - 1))
    if kind == "pulse_end":
        return bytes(max(0, size - 1)) + bytes([1])
    raise ValueError(f"unsupported probe pattern: {kind}")


@dataclass(frozen=True)
class ProbeCase:
    probe_id: str
    stability_group: str
    repetition: int
    purpose: str
    expected_safe: bool
    input_case: InputCase

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.probe.v1",
            "probe_id": self.probe_id,
            "stability_group": self.stability_group,
            "repetition": self.repetition,
            "purpose": self.purpose,
            "expected_safe": self.expected_safe,
            "input_case": self.input_case.to_dict(),
        }


def generate_probe_plan(
    contract: ContractGraphV2,
    *,
    base_seed: int = 0,
    max_executions: int = 32,
    repetitions: int = 2,
) -> tuple[ProbeCase, ...]:
    if max_executions <= 0:
        raise ValueError("max_executions must be positive")
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    runner_contract = contract.to_runner_contract()
    object_specs = {item.object_id: item for item in contract.objects}

    base_gpr: dict[str, Any] = {}
    base_objects: dict[str, dict[str, Any]] = {}
    for argument in runner_contract.arguments:
        slot = argument["slot"]
        if argument["kind"] == "integer":
            base_gpr[slot] = 0
        else:
            object_ref = str(argument["object_ref"])
            spec = object_specs[object_ref]
            base_gpr[slot] = {"object_ref": object_ref}
            base_objects[object_ref] = {
                "size": spec.min_size,
                "bytes_hex": _pattern(spec.min_size, "zero").hex(),
                "placement": "right",
            }

    definitions: list[tuple[str, str, bool, dict[str, Any], dict[str, Any]]] = [
        ("baseline", "baseline_zero", True, base_gpr, base_objects)
    ]
    argument_definitions: list[
        list[tuple[str, str, bool, dict[str, Any], dict[str, Any]]]
    ] = []
    for argument in runner_contract.arguments:
        slot = argument["slot"]
        current: list[tuple[str, str, bool, dict[str, Any], dict[str, Any]]] = []
        if argument["kind"] == "integer":
            for value in INTEGER_PROBES[1:]:
                gpr = dict(base_gpr)
                gpr[slot] = value
                current.append(
                    (f"integer_{slot}_{value}", f"integer_boundary:{slot}", True, gpr, base_objects)
                )
        else:
            object_ref = str(argument["object_ref"])
            spec = object_specs[object_ref]
            null_gpr = dict(base_gpr)
            null_gpr[slot] = {"null": True}
            # Keep every *other* pointer object intact so the InputCase
            # validator still sees the referenced objects. Only the probed
            # slot is nulled; non-null pointer slots retain their base payload.
            null_objects = {
                ref: dict(value)
                for ref, value in base_objects.items()
                if ref != object_ref
            }
            current.append(
                (f"null_{slot}", f"nullability:{slot}", False, null_gpr, null_objects)
            )
            sizes = (spec.min_size, min(16 * 1024, max(spec.min_size + 8, spec.min_size * 2)))
            for size in dict.fromkeys(sizes):
                for placement in ("left", "right"):
                    for pattern in ("zero", "pulse_start", "pulse_end", "repeat_a5"):
                        objects = dict(base_objects)
                        objects[object_ref] = {
                            "size": size,
                            "bytes_hex": _pattern(size, pattern).hex(),
                            "placement": placement,
                        }
                        current.append(
                            (
                                f"object_{slot}_{size}_{placement}_{pattern}",
                                f"object_boundary:{slot}",
                                True,
                                base_gpr,
                                objects,
                            )
                        )
        argument_definitions.append(current)

    # Allocate the bounded budget across argument slots in rounds. Exhausting every
    # pointer layout before considering the next integer slot made mixed contracts
    # observationally inert (for example, ptr + length always used length=0).
    for index in range(max((len(items) for items in argument_definitions), default=0)):
        for items in argument_definitions:
            if index < len(items):
                definitions.append(items[index])

    max_groups = max(1, max_executions // repetitions)
    definitions = definitions[:max_groups]
    probes: list[ProbeCase] = []
    for case_id, purpose, expected_safe, gpr, objects in definitions:
        case_seed = _seed(base_seed, contract.contract_id, case_id)
        input_case = InputCase.from_dict(
            {
                "schema_version": 1,
                "contract_id": contract.contract_id,
                "gpr": gpr,
                "objects": objects,
                "globals": {},
                "seed": case_seed,
            },
            contract=runner_contract,
        )
        for repetition in range(repetitions):
            if len(probes) >= max_executions:
                break
            probes.append(
                ProbeCase(
                    probe_id=f"{case_id}:r{repetition}",
                    stability_group=case_id,
                    repetition=repetition,
                    purpose=purpose,
                    expected_safe=expected_safe,
                    input_case=input_case,
                )
            )
    return tuple(probes)


@dataclass(frozen=True)
class ContractScore:
    contract_id: str
    valid: float
    stable: float
    effect: float
    boundary: float
    simple: float
    total: float
    observation_count: int
    safe_observation_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.contract-score.v1",
            "contract_id": self.contract_id,
            "components": {
                "valid": self.valid,
                "stable": self.stable,
                "effect": self.effect,
                "boundary": self.boundary,
                "simple": self.simple,
            },
            "weights": {
                "valid": 0.30,
                "stable": 0.25,
                "effect": 0.20,
                "boundary": 0.15,
                "simple": 0.10,
            },
            "total": self.total,
            "observation_count": self.observation_count,
            "safe_observation_count": self.safe_observation_count,
        }


def _stable_value(observation: dict[str, Any]) -> str:
    value = dict(observation)
    value.pop("elapsed_us", None)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _has_state_effect(observation: dict[str, Any]) -> bool:
    for collection in ("objects", "globals"):
        if any(
            item.get("changed_ranges")
            for item in (observation.get(collection) or {}).values()
        ):
            return True
    return False


def score_contract(
    contract: ContractGraphV2,
    probes: tuple[ProbeCase, ...],
    observations: tuple[dict[str, Any], ...],
) -> ContractScore:
    if len(probes) != len(observations):
        raise ContractValidationError(
            "probe and observation counts must match for contract scoring"
        )
    safe_pairs = [
        (probe, observation)
        for probe, observation in zip(probes, observations)
        if probe.expected_safe
    ]
    safe_count = len(safe_pairs)
    valid = (
        sum(observation.get("status") == "returned" for _, observation in safe_pairs)
        / safe_count
        if safe_count
        else 0.0
    )
    groups: dict[str, list[dict[str, Any]]] = {}
    for probe, observation in safe_pairs:
        groups.setdefault(probe.stability_group, []).append(observation)
    comparable_groups = [items for items in groups.values() if len(items) >= 2]
    stable = (
        sum(len({_stable_value(item) for item in items}) == 1 for items in comparable_groups)
        / len(comparable_groups)
        if comparable_groups
        else 0.0
    )
    returned = [
        observation
        for _, observation in safe_pairs
        if observation.get("status") == "returned"
    ]
    return_values = {
        json.dumps(
            observation.get("return"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for observation in returned
        if (observation.get("return") or {}).get("valid")
    }
    return_is_diverse = len(return_values) > 1
    effect = (
        sum(
            _has_state_effect(observation) or return_is_diverse
            for observation in returned
        )
        / len(returned)
        if returned
        else 0.0
    )
    boundary_pairs = [
        (probe, observation)
        for probe, observation in safe_pairs
        if probe.purpose.startswith("object_boundary:")
    ]
    boundary = (
        sum(observation.get("status") == "returned" for _, observation in boundary_pairs)
        / len(boundary_pairs)
        if boundary_pairs
        else valid
    )
    simple = 1.0 / (
        1.0
        + len(contract.arguments)
        + len(contract.objects)
        + int(contract.return_spec.observable)
    )
    total = 0.30 * valid + 0.25 * stable + 0.20 * effect + 0.15 * boundary + 0.10 * simple
    return ContractScore(
        contract_id=contract.contract_id,
        valid=valid,
        stable=stable,
        effect=effect,
        boundary=boundary,
        simple=simple,
        total=total,
        observation_count=len(observations),
        safe_observation_count=safe_count,
    )
