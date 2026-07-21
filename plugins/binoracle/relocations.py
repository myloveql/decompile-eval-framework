from __future__ import annotations

from typing import Any, Iterable


def relocations_for_symbol(
    relocations: Iterable[dict[str, Any]], target: dict[str, Any]
) -> tuple[dict[str, Any], ...]:
    start = int(target.get("value", 0))
    size = int(target.get("size", 0))
    end = start + size
    selected = []
    for item in relocations:
        if item.get("target_section") != target.get("section"):
            continue
        offset = int(item.get("offset", 0))
        if size and not start <= offset < end:
            continue
        selected.append(dict(item))
    return tuple(sorted(selected, key=lambda item: int(item.get("offset", 0))))
