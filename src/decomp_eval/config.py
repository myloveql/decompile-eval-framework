from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .util import sha256_json


DEFAULTS: dict[str, Any] = {
    "metrics": ["recompilable", "behavioral_pass"],
    "postprocessors": ["markdown_fence"],
    "executor": {"type": "local", "require_linux": True, "memory_mb": 2048, "max_file_mb": 64},
    "preflight": {"mode": "strict"},
    "output": {"root": "experiments/decompile_eval", "cache": "experiments/decompile_eval/cache"},
}


def _merge(default: dict[str, Any], custom: dict[str, Any]) -> dict[str, Any]:
    result = dict(default)
    for key, value in custom.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    config = _merge(DEFAULTS, raw)
    validate_config(config)
    config["_config_path"] = str(path.resolve())
    config["_config_hash"] = sha256_json(raw)
    return config


def validate_config(config: dict[str, Any]) -> None:
    errors: list[str] = []
    if not isinstance(config.get("datasets"), list) or not config.get("datasets"):
        errors.append("datasets must be a non-empty list")
    if not isinstance(config.get("decompilers"), list) or not config.get("decompilers"):
        errors.append("decompilers must be a non-empty list")
    dataset_ids: set[str] = set()
    for index, dataset in enumerate(config.get("datasets", [])):
        for field in ("id", "type", "path"):
            if not dataset.get(field):
                errors.append(f"datasets[{index}].{field} is required")
        if dataset.get("id") in dataset_ids:
            errors.append(f"duplicate dataset id: {dataset.get('id')}")
        dataset_ids.add(dataset.get("id"))
        protocol = dataset.get("evaluation_protocol")
        if protocol is not None and not isinstance(protocol, (str, dict)):
            errors.append(f"datasets[{index}].evaluation_protocol must be a string or mapping")
    ids: set[str] = set()
    for index, backend in enumerate(config.get("decompilers", [])):
        for field in ("id", "type"):
            if not backend.get(field):
                errors.append(f"decompilers[{index}].{field} is required")
        if backend.get("id") in ids:
            errors.append(f"duplicate decompiler id: {backend.get('id')}")
        ids.add(backend.get("id"))
        if backend.get("type") == "openai":
            if not backend.get("model"):
                errors.append(f"decompilers[{index}].model is required for type openai")
            if backend.get("api_mode", "responses") not in {"responses", "chat_completions"}:
                errors.append(
                    f"decompilers[{index}].api_mode must be responses or chat_completions"
                )
            provider = backend.get("provider", "openai")
            if provider != "openai" and not backend.get("base_url"):
                errors.append(
                    f"decompilers[{index}].base_url is required for provider {provider!r}"
                )
            required = backend.get("required_inputs", ["assembly"])
            if not isinstance(required, list) or not required:
                errors.append(f"decompilers[{index}].required_inputs must be a non-empty list")
            elif set(required) - {"assembly", "pseudocode"}:
                errors.append(
                    f"decompilers[{index}].required_inputs only supports assembly and pseudocode"
                )
    if config.get("preflight", {}).get("mode") not in {"strict", "warn", "off"}:
        errors.append("preflight.mode must be strict, warn, or off")
    if errors:
        raise ValueError("Invalid configuration:\n- " + "\n- ".join(errors))


def config_as_json(config: dict[str, Any]) -> str:
    return json.dumps(config, ensure_ascii=False, indent=2, default=str)
