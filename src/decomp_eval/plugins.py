from __future__ import annotations

from pathlib import Path
from typing import Any

from .backends import BUILTIN_BACKENDS
from .datasets import BUILTIN_DATASETS
from .metrics import BUILTIN_METRICS
from .postprocess import BUILTINS as BUILTIN_POSTPROCESSORS
from .protocols import BUILTIN_PROTOCOLS
from .util import load_object


def create_dataset(config: dict[str, Any], base_dir: Path):
    kind = config["type"]
    factory = BUILTIN_DATASETS.get(kind) or load_object(kind)
    adapter = factory(config, base_dir=base_dir)
    protocol_entry = config.get("evaluation_protocol", getattr(adapter, "default_protocol", None))
    if not protocol_entry:
        raise ValueError(f"Dataset {config['id']} does not declare an evaluation protocol")
    protocol_config = {"type": protocol_entry} if isinstance(protocol_entry, str) else dict(protocol_entry)
    kind = protocol_config.pop("type")
    protocol_factory = BUILTIN_PROTOCOLS.get(kind) or load_object(kind)
    adapter.evaluation_protocol = protocol_factory(
        protocol_config, adapter=adapter, base_dir=base_dir
    )
    return adapter


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
        "protocols": sorted(BUILTIN_PROTOCOLS),
    }
