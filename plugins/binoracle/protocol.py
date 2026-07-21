from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable


GPR_SLOTS = ("RDI", "RSI", "RDX", "RCX", "R8", "R9")
V1_ARGUMENT_SLOTS = frozenset(GPR_SLOTS[:3])
MAX_OBJECT_BYTES = 16 * 1024
MAX_OBJECTS = 3


class ProtocolError(ValueError):
    pass


def _hex_bytes(value: str, *, field: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ProtocolError(f"{field} must be valid hexadecimal") from error


def _relation_kind(value: dict[str, Any]) -> str:
    return str(value.get("kind", ""))


@dataclass(frozen=True)
class KnownContract:
    contract_id: str
    arguments: tuple[dict[str, Any], ...]
    return_kind: str
    return_observable: bool
    objects: tuple[dict[str, Any], ...]
    relations: tuple[dict[str, Any], ...] = ()
    dependencies: tuple[dict[str, Any], ...] = ()
    source: str = "explicit_known_contract_manifest"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "KnownContract":
        contract_id = str(value.get("contract_id", "K1"))
        arguments = tuple(dict(item) for item in value.get("arguments", []))
        if len(arguments) > len(GPR_SLOTS):
            raise ProtocolError("BinOracle V2 supports at most six arguments")
        seen_slots: set[str] = set()
        for argument in arguments:
            slot = str(argument.get("slot", "")).upper()
            kind = str(argument.get("kind") or next(iter(argument.get("kind_candidates", [])), "")).lower()
            if slot not in GPR_SLOTS:
                raise ProtocolError(f"unsupported argument slot: {slot}")
            if slot in seen_slots:
                raise ProtocolError(f"duplicate argument slot: {slot}")
            if kind not in {"integer", "pointer"}:
                raise ProtocolError(f"unsupported argument kind: {kind}")
            argument["slot"] = slot
            argument["kind"] = kind
            seen_slots.add(slot)

        return_value = value.get("return", {})
        return_kind = str(return_value.get("kind", "void_or_unknown")).lower()
        if return_kind not in {"void", "void_or_unknown", "integer", "integer_or_void", "pointer"}:
            raise ProtocolError(f"unsupported return kind: {return_kind}")
        observable = bool(return_value.get("observable", return_kind in {"integer", "pointer"}))

        objects = tuple(dict(item) for item in value.get("objects", []))
        if len(objects) > MAX_OBJECTS:
            raise ProtocolError(f"BinOracle V2 supports at most {MAX_OBJECTS} objects")
        object_ids: set[str] = set()
        for item in objects:
            object_id = str(item.get("object_id", ""))
            if not object_id or object_id in object_ids:
                raise ProtocolError("objects require unique non-empty object_id values")
            size = int(item.get("min_size", 1))
            if not 1 <= size <= MAX_OBJECT_BYTES:
                raise ProtocolError(f"contract object min_size must be between 1 and {MAX_OBJECT_BYTES}")
            alignment = int(item.get("alignment", 1))
            if alignment <= 0 or alignment > 4096 or alignment & (alignment - 1):
                raise ProtocolError("object alignment must be a power of two between 1 and 4096")
            item["object_id"] = object_id
            item["min_size"] = size
            item["alignment"] = alignment
            object_ids.add(object_id)
        for argument in arguments:
            if argument["kind"] == "pointer":
                object_ref = str(argument.get("object_ref", ""))
                if object_ref not in object_ids:
                    raise ProtocolError(f"pointer argument {argument['slot']} references missing {object_ref}")
                argument["object_ref"] = object_ref

        pointer_objects = {
            argument["object_ref"] for argument in arguments if argument["kind"] == "pointer"
        }
        relations = tuple(dict(item) for item in value.get("relations", []))
        for relation in relations:
            kind = _relation_kind(relation)
            if kind not in {"no_alias", "must_alias", "fixed_offset_alias", "length_within"}:
                raise ProtocolError(f"unsupported object relation: {kind or 'missing'}")
            if kind == "length_within":
                slot = str(relation.get("length_slot", "")).upper()
                object_ref = str(relation.get("object_ref", ""))
                if slot not in seen_slots or object_ref not in object_ids:
                    raise ProtocolError("length_within references an unknown slot or object")
                if next(item for item in arguments if item["slot"] == slot)["kind"] != "integer":
                    raise ProtocolError("length_within length_slot must be integer")
            else:
                left, right = str(relation.get("left", "")), str(relation.get("right", ""))
                if left not in object_ids or right not in object_ids or left == right:
                    raise ProtocolError("alias relation requires two distinct known objects")
                if left not in pointer_objects or right not in pointer_objects:
                    raise ProtocolError("alias relation requires objects referenced by pointer arguments")
                if kind in {"must_alias", "fixed_offset_alias"}:
                    raise ProtocolError(
                        f"{kind} must be represented by shared pointer object_ref values"
                    )
                relation["left"], relation["right"] = left, right
                if kind == "fixed_offset_alias":
                    relation["offset"] = int(relation.get("offset", 0))
        source = str(value.get("source", "explicit_known_contract_manifest"))
        if source not in {"explicit_known_contract_manifest", "automatic_contract_graph_v2", "llm_contract_proposal"}:
            raise ProtocolError(f"unsupported contract source: {source}")
        return cls(contract_id, arguments, return_kind, observable, objects, relations, tuple(dict(item) for item in value.get("dependencies", [])), source)

    def to_dict(self) -> dict[str, Any]:
        return {"contract_id": self.contract_id, "abi": "sysv-x86_64", "arguments": list(self.arguments), "return": {"kind": self.return_kind, "observable": self.return_observable}, "objects": list(self.objects), "relations": list(self.relations), "dependencies": list(self.dependencies), "source": self.source}


@dataclass(frozen=True)
class InputCase:
    contract_id: str
    gpr: dict[str, int | dict[str, Any]]
    objects: dict[str, dict[str, Any]]
    globals: dict[str, Any]
    seed: int
    virtual_read_bytes: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any], *, contract: KnownContract) -> "InputCase":
        if int(value.get("schema_version", 1)) != 1:
            raise ProtocolError("unsupported InputCase schema_version")
        contract_id = str(value.get("contract_id", ""))
        if contract_id != contract.contract_id:
            raise ProtocolError(f"InputCase contract_id {contract_id!r} does not match {contract.contract_id!r}")
        gpr = dict(value.get("gpr", {}))
        for argument in contract.arguments:
            slot = argument["slot"]
            if slot not in gpr:
                raise ProtocolError(f"InputCase is missing {slot}")
            raw = gpr[slot]
            if argument["kind"] == "integer":
                if isinstance(raw, bool) or not isinstance(raw, int):
                    raise ProtocolError(f"InputCase {slot} must be an integer")
            elif not isinstance(raw, dict) or not ("object_ref" in raw or raw.get("null") is True):
                raise ProtocolError(f"InputCase {slot} must contain object_ref or null=true")
            elif raw.get("null") is not True:
                object_ref = str(raw.get("object_ref", ""))
                if object_ref != argument["object_ref"]:
                    raise ProtocolError(
                        f"InputCase {slot} must reference contract object {argument['object_ref']}"
                    )
                raw["object_ref"] = object_ref
        objects = {str(key): dict(item) for key, item in value.get("objects", {}).items()}
        if len(objects) > MAX_OBJECTS:
            raise ProtocolError(f"InputCase exceeds the {MAX_OBJECTS}-object V2 limit")
        specs = {str(item["object_id"]): item for item in contract.objects}
        for object_id, item in objects.items():
            if object_id not in specs:
                raise ProtocolError(f"InputCase contains unknown object {object_id}")
            size = int(item.get("size", 0))
            if not 1 <= size <= MAX_OBJECT_BYTES:
                raise ProtocolError(f"{object_id}.size must be between 1 and {MAX_OBJECT_BYTES}")
            if size < int(specs[object_id]["min_size"]):
                raise ProtocolError(f"{object_id}.size is less than contract min_size")
            data = _hex_bytes(str(item.get("bytes_hex", "")), field=f"{object_id}.bytes_hex")
            if len(data) != size:
                raise ProtocolError(f"{object_id}.bytes_hex has {len(data)} bytes, expected {size}")
            placement = str(item.get("placement", "right"))
            if placement not in {"left", "right"}:
                raise ProtocolError(f"unsupported object placement: {placement}")
            item.update(size=size, bytes_hex=data.hex(), placement=placement)
        for argument in contract.arguments:
            if argument["kind"] == "pointer" and gpr[argument["slot"]].get("null") is not True:
                object_ref = str(gpr[argument["slot"]]["object_ref"])
                if object_ref not in objects:
                    raise ProtocolError(f"InputCase references missing object {object_ref}")
        _validate_relations(contract, gpr, objects)
        globals_value = dict(value.get("globals", {}))
        if globals_value:
            raise ProtocolError("custom global inputs are not supported")
        stream = str(value.get("virtual_read_bytes", ""))
        _hex_bytes(stream, field="virtual_read_bytes")
        return cls(contract_id, gpr, objects, globals_value, int(value.get("seed", 0)), stream)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "contract_id": self.contract_id, "gpr": self.gpr, "objects": self.objects, "globals": self.globals, "seed": self.seed, "virtual_read_bytes": self.virtual_read_bytes}


def _validate_relations(contract: KnownContract, gpr: dict[str, Any], objects: dict[str, dict[str, Any]]) -> None:
    pointer_references = {
        argument["object_ref"]: gpr[argument["slot"]]
        for argument in contract.arguments
        if argument["kind"] == "pointer"
    }
    for relation in contract.relations:
        kind = _relation_kind(relation)
        if kind == "length_within":
            length = gpr[str(relation["length_slot"]).upper()]
            if length < 0 or length > objects[str(relation["object_ref"])]["size"]:
                raise ProtocolError("length_within relation is violated")
            continue
        left, right = str(relation["left"]), str(relation["right"])
        left_value, right_value = pointer_references[left], pointer_references[right]
        left_null, right_null = left_value.get("null") is True, right_value.get("null") is True
        if left_null != right_null:
            raise ProtocolError(f"{kind} relation requires both pointer arguments to be null or non-null")
        if left_null:
            continue
        if kind == "must_alias":
            # Both GPR entries name the same object; the V2 runner interns it once.
            if left != right:
                raise ProtocolError("must_alias relation requires a shared object reference")
        elif kind == "fixed_offset_alias":
            # runner_main.c allocates each object independently and accepts no pointer
            # offset in InputCase, so only offset zero can be represented truthfully.
            if int(relation["offset"]) != 0:
                raise ProtocolError("non-zero fixed_offset_alias is unsupported by the runner")
            if left != right:
                raise ProtocolError("zero fixed_offset_alias requires a shared object reference")
        elif kind == "no_alias" and left == right:
            raise ProtocolError("no_alias relation is violated")


def default_input_case(contract: KnownContract, *, seed: int = 0) -> InputCase:
    gpr: dict[str, Any] = {}
    objects: dict[str, dict[str, Any]] = {}
    specs = {str(item["object_id"]): item for item in contract.objects}
    for argument in contract.arguments:
        if argument["kind"] == "integer":
            gpr[argument["slot"]] = 0
        else:
            ref = str(argument["object_ref"])
            spec = specs[ref]
            objects.setdefault(ref, {"size": int(spec["min_size"]), "bytes_hex": bytes(int(spec["min_size"])).hex(), "placement": "right"})
            gpr[argument["slot"]] = {"object_ref": ref}
    return InputCase.from_dict({"contract_id": contract.contract_id, "gpr": gpr, "objects": objects, "globals": {}, "seed": seed}, contract=contract)


def _changed_ranges(before: bytes, after: bytes) -> list[list[int]]:
    ranges: list[list[int]] = []
    start: int | None = None
    for index, (left, right) in enumerate(zip(before, after)):
        if left != right and start is None:
            start = index
        elif left == right and start is not None:
            ranges.append([start, index])
            start = None
    if start is not None:
        ranges.append([start, min(len(before), len(after))])
    return ranges


def normalize_observation(raw: dict[str, Any], *, contract: KnownContract, input_case: InputCase) -> dict[str, Any]:
    status = str(raw.get("status", "runner_error"))
    raw_return = dict(raw.get("return", {}))
    if contract.return_observable and status == "returned":
        if contract.return_kind == "pointer":
            return_value = ({"valid": True, "kind": "object_pointer", "object": raw_return["object"], "offset": int(raw_return.get("offset", 0))} if raw_return.get("object") else {"valid": False, "kind": "not_comparable", "reason": "pointer_outside_known_object"})
        else:
            return_value = {"valid": True, "kind": "integer", "rax": int(raw_return.get("rax", 0))}
    else:
        return_value = {"valid": False, "reason": "void_or_unknown"}
    objects: dict[str, Any] = {}
    for object_id, item in raw.get("objects", {}).items():
        before = _hex_bytes(str(item.get("before_hex", "")), field="before_hex")
        after = _hex_bytes(str(item.get("after_hex", "")), field="after_hex")
        objects[str(object_id)] = {"size": len(after), "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(after).hexdigest(), "changed_ranges": _changed_ranges(before, after), "after_bytes_hex": after.hex()}
    globals_: dict[str, Any] = {}
    for name, item in raw.get("globals", {}).items():
        before = _hex_bytes(str(item.get("before_hex", "")), field="global.before_hex")
        after = _hex_bytes(str(item.get("after_hex", "")), field="global.after_hex")
        globals_[str(name)] = {"size": len(after), "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(after).hexdigest(), "changed_ranges": _changed_ranges(before, after), "after_bytes_hex": after.hex()}
    return {"schema_version": 2, "contract_id": contract.contract_id, "seed": input_case.seed, "status": status, "signal": raw.get("signal"), "fault_address_class": raw.get("fault_address_class"), "object": raw.get("object"), "relative_offset": raw.get("relative_offset"), "return": return_value, "objects": objects, "globals": globals_, "external_events": list(raw.get("external_events", [])), "elapsed_us": int(raw.get("elapsed_us", 0))}


def jsonl(values: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in values)
