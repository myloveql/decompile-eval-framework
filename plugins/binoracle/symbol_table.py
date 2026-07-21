from __future__ import annotations

from typing import Any, Iterable


class SymbolTableError(ValueError):
    pass


def select_target_symbol(
    symbols: Iterable[dict[str, Any]], target_function: str
) -> dict[str, Any]:
    candidates = [
        item
        for item in symbols
        if item.get("name") == target_function
        and item.get("type") in {"FUNC", "NOTYPE"}
        and not item.get("undefined")
    ]
    if not candidates:
        raise SymbolTableError(f"target symbol was not found: {target_function}")
    return max(
        candidates,
        key=lambda item: (
            item.get("type") == "FUNC",
            item.get("binding") == "GLOBAL",
            int(item.get("size", 0)),
        ),
    )


def collect_global_objects(
    symbols: Iterable[dict[str, Any]],
    *,
    referenced_names: set[str] | None = None,
) -> tuple[dict[str, Any], ...]:
    referenced_names = referenced_names or set()
    result = []
    for item in symbols:
        if item.get("type") != "OBJECT" or item.get("undefined"):
            continue
        section = item.get("section")
        if section not in {".data", ".bss", ".rodata", ".data.rel.local", "COMMON"}:
            continue
        if item.get("binding") not in {"GLOBAL", "WEAK"} and item.get("name") not in referenced_names:
            continue
        result.append(dict(item))
    return tuple(sorted(result, key=lambda item: (str(item.get("section")), str(item.get("name")))))
