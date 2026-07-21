from __future__ import annotations

import re
from typing import Any


_FORBIDDEN_EXACT_KEYS = frozenset(
    {
        "signature",
        "function_head",
        "function_head_types",
        "typemap",
        "livein",
        "liveout",
        "io_pairs",
        "wrapper",
        "cpp_wrapper",
        "source",
        "source_code",
        "reference",
        "reference_source",
        "ground_truth",
        "test",
        "tests",
        "test_case",
        "test_cases",
        "oracle",
        "oracle_context",
        "compile_context",
        "expected",
        "expected_output",
    }
)
_FORBIDDEN_PREFIXES = (
    "reference_",
    "ground_truth_",
    "expected_",
    "oracle_",
    "test_",
)


def normalize_metadata_key(value: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def is_private_metadata_key(value: Any) -> bool:
    key = normalize_metadata_key(value)
    return key in _FORBIDDEN_EXACT_KEYS or key.startswith(_FORBIDDEN_PREFIXES)


def find_private_metadata_paths(value: Any, prefix: str = "metadata") -> list[str]:
    """Return deterministic paths to forbidden fields nested at any depth."""

    found: list[str] = []
    if isinstance(value, dict):
        for key in sorted(value, key=lambda item: str(item)):
            nested = value[key]
            path = f"{prefix}.{key}"
            if is_private_metadata_key(key):
                found.append(path)
            found.extend(find_private_metadata_paths(nested, path))
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            found.extend(find_private_metadata_paths(nested, f"{prefix}[{index}]"))
    return found
