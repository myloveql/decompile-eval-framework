from __future__ import annotations

import math
from typing import Any


def strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(strict_equal(actual[k], expected[k]) for k in actual)
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(strict_equal(a, b) for a, b in zip(actual, expected))
    if isinstance(actual, float):
        return math.isclose(actual, expected)
    return actual == expected


def command_log(result) -> dict[str, Any]:
    return {
        "command": result.command,
        "returncode": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-8000:],
        "elapsed_seconds": result.elapsed_seconds,
        "timed_out": result.timed_out,
    }
