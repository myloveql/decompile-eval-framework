from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from .protocol import GPR_SLOTS, KnownContract, MAX_OBJECT_BYTES
from .schemas import ContractGraph


SCHEMA_VERSION = "binoracle.contract.v2"
SUPPORTED_ABI = "x86_64_sysv"
SUPPORTED_ARGUMENT_KINDS = frozenset({"integer", "pointer"})
SUPPORTED_RETURN_KINDS = frozenset(
    {"void", "unknown", "integer", "object_pointer"}
)


class ContractValidationError(ValueError):
    """Raised when a contract cannot be represented without ambiguity or leakage."""


def _confidence(value: Any, *, field: str) -> float:
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ContractValidationError(f"{field} must be between 0 and 1")
    return result


def _unique_strings(values: Iterable[Any], *, field: str) -> tuple[str, ...]:
    result = tuple(str(item) for item in values)
    if not result:
        raise ContractValidationError(f"{field} must not be empty")
    if len(result) != len(set(result)):
        raise ContractValidationError(f"{field} contains duplicate values")
    return result


def normalize_abi(value: str) -> str:
    normalized = value.lower().replace("-", "_")
    if normalized in {"sysv_x86_64", "x86_64_sysv", "amd64_sysv"}:
        return SUPPORTED_ABI
    raise ContractValidationError(f"unsupported ABI: {value}")


@dataclass(frozen=True, order=True)
class MemoryRange:
    """A half-open byte range [start, end) relative to an object base."""

    start: int
    end: int

    @classmethod
    def from_value(cls, value: Any, *, field: str) -> "MemoryRange":
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ContractValidationError(f"{field} must be [start, end]")
        start, end = int(value[0]), int(value[1])
        if start < 0 or end <= start:
            raise ContractValidationError(
                f"{field} must be a non-empty non-negative half-open range"
            )
        return cls(start, end)

    def to_list(self) -> list[int]:
        return [self.start, self.end]


@dataclass(frozen=True)
class ObjectContractV2:
    object_id: str
    argument_slot: str
    min_size: int
    alignment: int
    read_ranges: tuple[MemoryRange, ...] = ()
    write_ranges: tuple[MemoryRange, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ObjectContractV2":
        object_id = str(value.get("object_id", ""))
        if not object_id:
            raise ContractValidationError("object.object_id must not be empty")
        argument_slot = str(value.get("argument_slot", "")).upper()
        if argument_slot not in GPR_SLOTS:
            raise ContractValidationError(
                f"unsupported object argument slot: {argument_slot}"
            )
        min_size = int(value.get("min_size", 0))
        if not 1 <= min_size <= MAX_OBJECT_BYTES:
            raise ContractValidationError(
                f"object.min_size must be between 1 and {MAX_OBJECT_BYTES}"
            )
        alignment = int(value.get("alignment", 1))
        if alignment <= 0 or alignment > 4096 or alignment & (alignment - 1):
            raise ContractValidationError(
                "object.alignment must be a power of two between 1 and 4096"
            )
        reads = tuple(
            MemoryRange.from_value(item, field="object.read_ranges")
            for item in value.get("read_ranges", [])
        )
        writes = tuple(
            MemoryRange.from_value(item, field="object.write_ranges")
            for item in value.get("write_ranges", [])
        )
        for item in reads + writes:
            if item.end > min_size:
                raise ContractValidationError(
                    f"object range [{item.start}, {item.end}) exceeds min_size {min_size}"
                )
        return cls(
            object_id=object_id,
            argument_slot=argument_slot,
            min_size=min_size,
            alignment=alignment,
            read_ranges=reads,
            write_ranges=writes,
            evidence_ids=tuple(str(item) for item in value.get("evidence_ids", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_id": self.object_id,
            "argument_slot": self.argument_slot,
            "min_size": self.min_size,
            "alignment": self.alignment,
            "read_ranges": [item.to_list() for item in self.read_ranges],
            "write_ranges": [item.to_list() for item in self.write_ranges],
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class ArgumentContractV2:
    slot: int
    register: str
    kind_candidates: tuple[str, ...]
    confidence: float
    evidence_ids: tuple[str, ...] = ()
    object_ref: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ArgumentContractV2":
        slot = int(value.get("slot", -1))
        if slot not in range(len(GPR_SLOTS)):
            raise ContractValidationError("argument.slot must be between 0 and 5")
        expected_register = GPR_SLOTS[slot]
        register = str(value.get("register", expected_register)).upper()
        if register != expected_register:
            raise ContractValidationError(
                f"argument slot {slot} must use {expected_register}, got {register}"
            )
        kinds = _unique_strings(
            (str(item).lower() for item in value.get("kind_candidates", [])),
            field="argument.kind_candidates",
        )
        unsupported = set(kinds) - SUPPORTED_ARGUMENT_KINDS
        if unsupported:
            raise ContractValidationError(
                "unsupported argument kinds: " + ", ".join(sorted(unsupported))
            )
        object_ref = value.get("object_ref")
        object_ref = str(object_ref) if object_ref is not None else None
        if kinds[0] == "pointer" and not object_ref:
            raise ContractValidationError(
                f"primary pointer candidate in {register} requires object_ref"
            )
        if "pointer" not in kinds and object_ref is not None:
            raise ContractValidationError(
                f"non-pointer argument {register} must not contain object_ref"
            )
        return cls(
            slot=slot,
            register=register,
            kind_candidates=kinds,
            confidence=_confidence(value.get("confidence", 0.0), field="argument.confidence"),
            evidence_ids=tuple(str(item) for item in value.get("evidence_ids", [])),
            object_ref=object_ref,
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "slot": self.slot,
            "register": self.register,
            "kind_candidates": list(self.kind_candidates),
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
        }
        if self.object_ref is not None:
            value["object_ref"] = self.object_ref
        return value


@dataclass(frozen=True)
class ReturnContractV2:
    kind_candidates: tuple[str, ...]
    confidence: float
    observable: bool
    evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ReturnContractV2":
        kinds = _unique_strings(
            (str(item).lower() for item in value.get("kind_candidates", [])),
            field="return.kind_candidates",
        )
        unsupported = set(kinds) - SUPPORTED_RETURN_KINDS
        if unsupported:
            raise ContractValidationError(
                "unsupported return kinds: " + ", ".join(sorted(unsupported))
            )
        observable = bool(value.get("observable", False))
        if observable and kinds[0] in {"void", "unknown"}:
            raise ContractValidationError(
                "void/unknown primary return candidate cannot be observable"
            )
        return cls(
            kind_candidates=kinds,
            confidence=_confidence(value.get("confidence", 0.0), field="return.confidence"),
            observable=observable,
            evidence_ids=tuple(str(item) for item in value.get("evidence_ids", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind_candidates": list(self.kind_candidates),
            "confidence": self.confidence,
            "observable": self.observable,
            "evidence_ids": list(self.evidence_ids),
        }


def _validate_relations(
    values: Iterable[dict[str, Any]],
    object_ids: Iterable[str],
    arguments: Iterable[ArgumentContractV2],
) -> tuple[dict[str, Any], ...]:
    known_objects = set(object_ids)
    by_register = {item.register: item for item in arguments}
    result: list[dict[str, Any]] = []
    for raw in values:
        relation = dict(raw)
        kind = str(relation.get("kind", ""))
        if kind not in {"no_alias", "must_alias", "fixed_offset_alias", "length_within"}:
            raise ContractValidationError(f"unsupported object relation: {kind or 'missing'}")
        if kind == "length_within":
            slot = str(relation.get("length_slot", "")).upper()
            object_ref = str(relation.get("object_ref", ""))
            if object_ref not in known_objects or slot not in by_register:
                raise ContractValidationError("length_within references an unknown slot or object")
            if by_register[slot].kind_candidates[0] != "integer":
                raise ContractValidationError("length_within length_slot must have integer primary kind")
            relation["length_slot"] = slot
            relation["object_ref"] = object_ref
        else:
            left, right = str(relation.get("left", "")), str(relation.get("right", ""))
            if left not in known_objects or right not in known_objects or left == right:
                raise ContractValidationError("alias relation requires two distinct known objects")
            relation["left"], relation["right"] = left, right
            if kind == "fixed_offset_alias":
                try:
                    relation["offset"] = int(relation["offset"])
                except (KeyError, TypeError, ValueError) as error:
                    raise ContractValidationError("fixed_offset_alias requires an integer offset") from error
                if relation["offset"] != 0:
                    raise ContractValidationError(
                        "non-zero fixed_offset_alias is unsupported by the runner"
                    )
        result.append(relation)
    return tuple(result)


@dataclass(frozen=True)
class ContractGraphV2:
    sample_id: str
    contract_id: str
    abi: str
    arguments: tuple[ArgumentContractV2, ...]
    objects: tuple[ObjectContractV2, ...]
    return_spec: ReturnContractV2
    relations: tuple[dict[str, Any], ...] = ()
    globals: tuple[dict[str, Any], ...] = ()
    dependencies: tuple[dict[str, Any], ...] = ()
    unsupported_reasons: tuple[str, ...] = ()
    confidence: float = 0.0
    evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ContractGraphV2":
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ContractValidationError(
                f"unsupported contract schema: {value.get('schema_version')!r}"
            )
        sample_id = str(value.get("sample_id", ""))
        contract_id = str(value.get("contract_id", ""))
        if not sample_id or not contract_id:
            raise ContractValidationError("sample_id and contract_id must not be empty")
        arguments = tuple(
            ArgumentContractV2.from_dict(item) for item in value.get("arguments", [])
        )
        slots = [item.slot for item in arguments]
        if slots != sorted(slots) or len(slots) != len(set(slots)):
            raise ContractValidationError(
                "arguments must have unique slots in ascending ABI order"
            )
        objects = tuple(
            ObjectContractV2.from_dict(item) for item in value.get("objects", [])
        )
        object_ids = [item.object_id for item in objects]
        if len(object_ids) != len(set(object_ids)):
            raise ContractValidationError("objects contain duplicate object_id values")
        if len(objects) > 3:
            raise ContractValidationError(
                "Phase 2 contract graph supports at most three pointer objects"
            )
        by_id = {item.object_id: item for item in objects}
        for argument in arguments:
            if argument.object_ref is None:
                continue
            obj = by_id.get(argument.object_ref)
            if obj is None:
                raise ContractValidationError(
                    f"argument {argument.register} references missing {argument.object_ref}"
                )
            if obj.argument_slot != argument.register:
                raise ContractValidationError(
                    f"object {obj.object_id} belongs to {obj.argument_slot}, not {argument.register}"
                )
        return cls(
            sample_id=sample_id,
            contract_id=contract_id,
            abi=normalize_abi(str(value.get("abi", ""))),
            arguments=arguments,
            objects=objects,
            return_spec=ReturnContractV2.from_dict(value.get("return", {})),
            relations=_validate_relations(value.get("relations", []), object_ids, arguments),
            globals=tuple(dict(item) for item in value.get("globals", [])),
            dependencies=tuple(dict(item) for item in value.get("dependencies", [])),
            unsupported_reasons=tuple(
                str(item) for item in value.get("unsupported_reasons", [])
            ),
            confidence=_confidence(value.get("confidence", 0.0), field="confidence"),
            evidence_ids=tuple(str(item) for item in value.get("evidence_ids", [])),
        )

    @classmethod
    def from_static_contract(
        cls,
        contract: ContractGraph,
        *,
        sample_id: str,
        globals: Iterable[dict[str, Any]] = (),
        dependencies: Iterable[dict[str, Any]] = (),
    ) -> "ContractGraphV2":
        slot_numbers = {register: index for index, register in enumerate(GPR_SLOTS)}
        unsupported_reasons: list[str] = []
        unsupported_slots = [
            item.slot for item in contract.arguments if item.slot not in slot_numbers
        ]
        if unsupported_slots:
            unsupported_reasons.append(
                "unsupported_argument_slots:" + ",".join(unsupported_slots)
            )
        objects = []
        supported_object_ids = {
            item.object_ref
            for item in contract.arguments
            if item.slot in slot_numbers and item.object_ref is not None
        }
        for item in contract.objects:
            if item.object_id not in supported_object_ids:
                continue
            min_size = item.min_size
            if min_size > MAX_OBJECT_BYTES:
                unsupported_reasons.append(
                    f"object_exceeds_max_bytes:{item.object_id}:{min_size}"
                )
                min_size = MAX_OBJECT_BYTES
            reads = [
                [offset, min(offset + width, min_size)]
                for offset, width in item.reads
                if offset < min_size
            ]
            writes = [
                [offset, min(offset + width, min_size)]
                for offset, width in item.writes
                if offset < min_size
            ]
            objects.append(
                {
                    "object_id": item.object_id,
                    "argument_slot": item.argument_slot,
                    "min_size": min_size,
                    "alignment": item.alignment,
                    "read_ranges": reads,
                    "write_ranges": writes,
                    "evidence_ids": list(item.reads and ("static_memory_access",) or ()),
                }
            )
        return_kind_map = {
            "void_or_unknown": ["void", "unknown"],
            "integer_or_void": ["integer", "void"],
            "pointer": ["object_pointer"],
        }
        payload = {
            "schema_version": SCHEMA_VERSION,
            "sample_id": sample_id,
            "contract_id": contract.contract_id,
            "abi": contract.abi,
            "arguments": [
                {
                    "slot": slot_numbers[item.slot],
                    "register": item.slot,
                    "kind_candidates": list(item.kind_candidates),
                    "confidence": item.confidence,
                    "evidence_ids": list(item.evidence),
                    **({"object_ref": item.object_ref} if item.object_ref else {}),
                }
                for item in contract.arguments
                if item.slot in slot_numbers
            ],
            "objects": objects,
            "return": {
                "kind_candidates": return_kind_map.get(
                    contract.return_spec.kind, [contract.return_spec.kind]
                ),
                "confidence": contract.return_spec.confidence,
                "observable": contract.return_spec.observable,
                "evidence_ids": list(contract.return_spec.evidence),
            },
            "relations": [],
            "globals": [dict(item) for item in globals],
            "dependencies": [dict(item) for item in dependencies]
            or [{"name": item} for item in contract.dependencies],
            "unsupported_reasons": unsupported_reasons,
            "confidence": contract.confidence,
            "evidence_ids": [],
        }
        return cls.from_dict(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "sample_id": self.sample_id,
            "contract_id": self.contract_id,
            "abi": self.abi,
            "arguments": [item.to_dict() for item in self.arguments],
            "objects": [item.to_dict() for item in self.objects],
            "return": self.return_spec.to_dict(),
            "relations": list(self.relations),
            "globals": list(self.globals),
            "dependencies": list(self.dependencies),
            "unsupported_reasons": list(self.unsupported_reasons),
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
        }

    @property
    def content_hash(self) -> str:
        encoded = json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_runner_contract(self) -> KnownContract:
        """Select each primary candidate for the versioned V2 ABI runner.

        This conversion is deliberately explicit: it does not claim the primary
        choices are ground truth and records an automatic-contract source tag.
        """

        if self.unsupported_reasons:
            raise ContractValidationError(
                "cannot run unsupported contract: " + ", ".join(self.unsupported_reasons)
            )
        if len(self.objects) > 3:
            raise ContractValidationError("the ABI runner supports at most three independently allocated objects")
        parent = {item.object_id: item.object_id for item in self.objects}

        def find(object_id: str) -> str:
            while parent[object_id] != object_id:
                parent[object_id] = parent[parent[object_id]]
                object_id = parent[object_id]
            return object_id

        def union(left: str, right: str) -> None:
            left_root, right_root = find(left), find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        for relation in self.relations:
            kind = str(relation["kind"])
            if kind == "must_alias" or (
                kind == "fixed_offset_alias" and int(relation["offset"]) == 0
            ):
                union(str(relation["left"]), str(relation["right"]))
            elif kind == "fixed_offset_alias":
                raise ContractValidationError(
                    "non-zero fixed_offset_alias is unsupported by the runner"
                )

        canonical = {object_id: find(object_id) for object_id in parent}
        for relation in self.relations:
            if str(relation["kind"]) == "no_alias" and canonical[str(relation["left"])] == canonical[str(relation["right"])]:
                raise ContractValidationError("no_alias conflicts with an alias relation")
        arguments = []
        for item in self.arguments:
            kind = item.kind_candidates[0]
            value: dict[str, Any] = {"slot": item.register, "kind": kind}
            if kind == "pointer":
                if item.object_ref is None:
                    raise ContractValidationError(
                        f"primary pointer candidate in {item.register} has no object_ref"
                    )
                value["object_ref"] = canonical[item.object_ref]
            arguments.append(value)
        runner_objects: dict[str, dict[str, Any]] = {}
        for item in self.objects:
            object_id = canonical[item.object_id]
            current = runner_objects.setdefault(
                object_id,
                {
                    "object_id": object_id,
                    "min_size": item.min_size,
                    "alignment": item.alignment,
                },
            )
            current["min_size"] = max(int(current["min_size"]), item.min_size)
            current["alignment"] = max(int(current["alignment"]), item.alignment)
        return_kind = self.return_spec.kind_candidates[0]
        if return_kind == "unknown":
            return_kind = "void_or_unknown"
        elif return_kind == "object_pointer":
            return_kind = "pointer"
        payload = {
            "contract_id": self.contract_id,
            "arguments": arguments,
            "return": {
                "kind": return_kind,
                "observable": self.return_spec.observable,
            },
            "objects": list(runner_objects.values()),
            "relations": [
                relation
                for relation in self.relations
                if str(relation["kind"]) not in {"must_alias", "fixed_offset_alias"}
            ],
            "dependencies": list(self.dependencies),
            "source": "automatic_contract_graph_v2",
        }
        return KnownContract.from_dict(payload)
