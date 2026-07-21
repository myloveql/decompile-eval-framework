from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .contract_v2 import ContractGraphV2
from .dependencies import LIBC_WHITELIST, STUBBED_DEPENDENCIES
from .protocol import GPR_SLOTS, MAX_OBJECT_BYTES


@dataclass(frozen=True)
class CapabilityRequirement:
    contract_id: str
    required_slots: tuple[str, ...]
    object_count: int
    relation_kinds: tuple[str, ...]
    dependencies: tuple[str, ...]
    status: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.capability-requirement.v1",
            "contract_id": self.contract_id,
            "required_slots": list(self.required_slots),
            "object_count": self.object_count,
            "relation_kinds": list(self.relation_kinds),
            "dependencies": list(self.dependencies),
            "status": self.status,
            "reasons": list(self.reasons),
        }


def assess_capability(
    contract: ContractGraphV2, *, runner_version: str = "binoracle-harness-H2"
) -> CapabilityRequirement:
    del runner_version
    reasons: list[str] = []
    slots = tuple(argument.register for argument in contract.arguments)
    if any(slot not in GPR_SLOTS for slot in slots):
        reasons.append("unsupported_argument_slot")
    if len(contract.objects) > 3:
        reasons.append("object_count_exceeds_v2_limit")
    if any(item.min_size > MAX_OBJECT_BYTES for item in contract.objects):
        reasons.append("object_size_exceeds_limit")
    relation_kinds: list[str] = []
    for relation in contract.relations:
        kind = str(relation.get("kind", ""))
        relation_kinds.append(kind)
        if kind not in {"no_alias", "must_alias", "fixed_offset_alias", "length_within"}:
            reasons.append(f"unsupported_relation:{kind or 'missing'}")
    dependencies = tuple(sorted(str(item.get("name", item)) for item in contract.dependencies))
    unsupported_dependencies = [
        name
        for name in dependencies
        if name and name not in LIBC_WHITELIST and name not in STUBBED_DEPENDENCIES
    ]
    if unsupported_dependencies:
        reasons.extend(
            f"unsupported_unknown_external_dependency:{name}"
            for name in unsupported_dependencies
        )
    uses_stub = any(name in STUBBED_DEPENDENCIES for name in dependencies)
    if contract.unsupported_reasons:
        reasons.extend(contract.unsupported_reasons)
    status = "unsupported" if reasons else (
        "supported_with_stub" if uses_stub else "supported"
    )
    return CapabilityRequirement(
        contract_id=contract.contract_id,
        required_slots=slots,
        object_count=len(contract.objects),
        relation_kinds=tuple(sorted(set(relation_kinds))),
        dependencies=dependencies,
        status=status,
        reasons=tuple(sorted(set(reasons))),
    )


def assess_capabilities(contracts: Iterable[ContractGraphV2]) -> tuple[CapabilityRequirement, ...]:
    return tuple(assess_capability(contract) for contract in contracts)
