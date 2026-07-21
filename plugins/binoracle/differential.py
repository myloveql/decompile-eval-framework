from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ObservationDifference:
    probe_id: str
    kinds: tuple[str, ...]
    details: dict[str, Any]

    @property
    def equivalent(self) -> bool:
        return not self.kinds

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.difference.v1",
            "probe_id": self.probe_id,
            "equivalent": self.equivalent,
            "kinds": list(self.kinds),
            "details": self.details,
        }


def _memory_after(value: dict[str, Any], collection: str) -> dict[str, str | None]:
    return {
        str(name): item.get("after_bytes_hex")
        for name, item in (value.get(collection) or {}).items()
    }


def compare_observations(
    probe_id: str,
    original: dict[str, Any],
    candidate: dict[str, Any],
    *,
    compare_return: bool,
    compare_globals: bool = True,
) -> ObservationDifference:
    kinds: list[str] = []
    details: dict[str, Any] = {}
    if original.get("status") != candidate.get("status"):
        kinds.append("process_status")
        details["process_status"] = {
            "original": original.get("status"),
            "candidate": candidate.get("status"),
        }
    elif original.get("status") == "signal":
        original_fault = (
            original.get("signal"),
            original.get("fault_address_class"),
            original.get("relative_offset"),
        )
        candidate_fault = (
            candidate.get("signal"),
            candidate.get("fault_address_class"),
            candidate.get("relative_offset"),
        )
        if original_fault != candidate_fault:
            kinds.append("signal")
            details["signal"] = {
                "original": original_fault,
                "candidate": candidate_fault,
            }
    if compare_return and original.get("return") != candidate.get("return"):
        kinds.append("return")
        details["return"] = {
            "original": original.get("return"),
            "candidate": candidate.get("return"),
        }
    original_memory = _memory_after(original, "objects")
    candidate_memory = _memory_after(candidate, "objects")
    if original_memory != candidate_memory:
        kinds.append("memory")
        details["memory"] = {
            "original": original_memory,
            "candidate": candidate_memory,
        }
    if compare_globals:
        original_globals = _memory_after(original, "globals")
        candidate_globals = _memory_after(candidate, "globals")
        if original_globals != candidate_globals:
            kinds.append("global")
            details["global"] = {
                "original": original_globals,
                "candidate": candidate_globals,
            }
    original_events = list(original.get("external_events") or [])
    candidate_events = list(candidate.get("external_events") or [])
    if original_events != candidate_events:
        kinds.append("external_event")
        details["external_event"] = {
            "original": original_events,
            "candidate": candidate_events,
        }
    return ObservationDifference(probe_id, tuple(kinds), details)
