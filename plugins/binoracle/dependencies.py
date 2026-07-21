from __future__ import annotations

from typing import Any, Iterable


LIBC_WHITELIST = frozenset(
    {
        "abort",
        "calloc",
        "free",
        "malloc",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "printf",
        "realloc",
        "strcmp",
        "strcpy",
        "strlen",
        "strncmp",
        "strncpy",
        "__stack_chk_fail",
    }
)

# These functions are supplied by the versioned Harness V2 runtime rather than
# accidentally resolved from the host libc.
STUBBED_DEPENDENCIES = frozenset({"puts", "read"})

IGNORED_LINKER_SYMBOLS = frozenset({"_GLOBAL_OFFSET_TABLE_"})


def classify_dependencies(
    undefined_symbols: Iterable[str],
    target_relocations: Iterable[dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    undefined = set(undefined_symbols)
    direct = {
        str(item.get("symbol"))
        for item in target_relocations
        if item.get("symbol") and item.get("symbol") in undefined
    }
    result = []
    for name in sorted(undefined):
        if name in IGNORED_LINKER_SYMBOLS:
            classification = "linker_internal"
            supported = True
        elif name in LIBC_WHITELIST:
            classification = "whitelisted_libc"
            supported = True
        elif name in STUBBED_DEPENDENCIES:
            classification = "deterministic_harness_stub"
            supported = True
        else:
            classification = "unknown_external"
            supported = False
        result.append(
            {
                "name": name,
                "direct_from_target": name in direct,
                "classification": classification,
                "supported": supported,
            }
        )
    return tuple(result)


def unsupported_direct_dependencies(
    dependencies: Iterable[dict[str, Any]],
) -> tuple[str, ...]:
    return tuple(
        str(item["name"])
        for item in dependencies
        if item.get("direct_from_target") and not item.get("supported")
    )
