from __future__ import annotations

from pathlib import Path
from typing import Any

from .backends import BUILTIN_BACKENDS
from .datasets import BUILTIN_DATASETS
from .metrics import BUILTIN_METRICS
from .postprocess import BUILTINS as BUILTIN_POSTPROCESSORS
from .util import load_object


def create_dataset(config: dict[str, Any], base_dir: Path):
    kind = config["type"]
    factory = BUILTIN_DATASETS.get(kind) or load_object(kind)
    return factory(config, base_dir=base_dir)


def create_backend(config: dict[str, Any], base_dir: Path):
    kind = config["type"]
    factory = BUILTIN_BACKENDS.get(kind) or load_object(kind)
    return factory(config, base_dir=base_dir)


def plugin_inventory() -> dict[str, list[str]]:
    return {
        "datasets": sorted(BUILTIN_DATASETS),
        "backends": sorted(BUILTIN_BACKENDS),
        "metrics": sorted(BUILTIN_METRICS),
        "postprocessors": sorted(BUILTIN_POSTPROCESSORS),
    }

