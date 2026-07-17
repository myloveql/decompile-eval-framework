from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import DecompileRequest, DecompileResult, EvaluationEvidence
from .util import sha256_json, sha256_text


SELECTION_ONLY_DATASET_FIELDS = {
    "selection_manifest", "limit", "optimizations", "languages", "splits", "split"
}


def evaluation_dataset_config(dataset_config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in dataset_config.items()
        if key not in SELECTION_ONLY_DATASET_FIELDS
    }


def generation_key(
    request: DecompileRequest | dict[str, Any],
    backend_config: dict[str, Any],
    backend_version: str,
    required_inputs: tuple[str, ...] | list[str],
) -> str:
    request_value = request.to_dict() if isinstance(request, DecompileRequest) else dict(request)
    # Older request.json files predate these optional fields. Missing and null carry
    # the same public-input meaning and must produce the same generation identity.
    request_value = dict(request_value)
    request_value.setdefault("binary", None)
    request_value.setdefault("pseudocode", None)
    request_value.setdefault("compile_context", None)
    request_value.setdefault("metadata", {})
    def normalize_backend(value: Any, *, parent: str = "") -> Any:
        if isinstance(value, dict):
            normalized = {}
            for key, item in value.items():
                if re.search(r"(api[_-]?key|token|password|secret)", key, re.I):
                    continue
                if key == "batch_size" or (parent == "plugin_config" and key == "max_concurrency"):
                    continue
                normalized_item = normalize_backend(item, parent=key)
                if isinstance(item, dict) and not normalized_item:
                    continue
                normalized[key] = normalized_item
            return normalized
        if isinstance(value, list):
            return [normalize_backend(item, parent=parent) for item in value]
        return value

    normalized_backend = normalize_backend(backend_config)
    return sha256_json({
        "schema": "generation-key/v1",
        "request": request_value,
        "backend": normalized_backend,
        "backend_version": str(backend_version),
        "required_inputs": list(required_inputs),
    })


def candidate_key(generation_cache_key: str, postprocessors: list[Any]) -> str:
    return sha256_json({
        "schema": "candidate-key/v1",
        "generation_key": generation_cache_key,
        "postprocessors": postprocessors,
    })


def evaluation_key(
    *, sample_content_hash: str, candidate_code: str, dataset_config: dict[str, Any],
    protocol_descriptor: dict[str, Any], protocol_config: dict[str, Any],
    executor_config: dict[str, Any],
) -> str:
    evaluation_config = evaluation_dataset_config(dataset_config)
    return sha256_json({
        "schema": "evaluation-key/v1",
        "sample_content_hash": sample_content_hash,
        "candidate_sha256": sha256_text(candidate_code),
        "dataset_evaluation": evaluation_config,
        "protocol": protocol_descriptor,
        "protocol_config": protocol_config,
        "executor": executor_config,
    })


class LayeredCache:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, layer: str, key: str) -> Path:
        return self.root / layer / f"{key}.json"

    def generation_path(self, key: str) -> Path:
        return self._path("generations", key)

    def candidate_path(self, key: str) -> Path:
        return self._path("candidates", key)

    def evaluation_path(self, key: str) -> Path:
        return self._path("evaluations", key)

    @staticmethod
    def _read(path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _write(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")

    def load_generation(self, key: str) -> DecompileResult | None:
        value = self._read(self.generation_path(key))
        if value is None:
            return None
        return DecompileResult(**value["result"])

    def save_generation(
        self, key: str, result: DecompileResult, *, identity: dict[str, Any], imported_from: str | None = None
    ) -> None:
        path = self.generation_path(key)
        existing = self._read(path)
        serialized = asdict(result)
        if existing is not None:
            old = existing.get("result", {})
            semantic_fields = (
                "success", "raw_output", "code", "reason", "backend_version",
            )
            if any(old.get(field) != serialized.get(field) for field in semantic_fields):
                raise ValueError(
                    f"Generation cache conflict for key {key}; preserve both experiments by "
                    "using distinct backend version/config values or a different cache directory"
                )
            return
        self._write(path, {
            "schema": "generation-cache/v1",
            "key": key,
            "identity": identity,
            "result": serialized,
            "imported_from": imported_from,
        })

    def load_candidate(self, key: str) -> dict[str, Any] | None:
        return self._read(self.candidate_path(key))

    def save_candidate(
        self, key: str, code: str, actions: list[dict[str, Any]], *,
        generation_cache_key: str, identity: dict[str, Any], imported_from: str | None = None,
    ) -> None:
        path = self.candidate_path(key)
        existing = self._read(path)
        if existing is not None and (
            existing.get("code") != code or existing.get("actions", []) != actions
        ):
            raise ValueError(f"Candidate cache conflict for key {key}")
        self._write(path, {
            "schema": "candidate-cache/v1",
            "key": key,
            "generation_key": generation_cache_key,
            "candidate_sha256": sha256_text(code),
            "code": code,
            "actions": actions,
            "identity": identity,
            "imported_from": imported_from,
        })

    def load_evaluation(self, key: str) -> EvaluationEvidence | None:
        value = self._read(self.evaluation_path(key))
        if value is None:
            return None
        evidence = dict(value["evidence"])
        evidence["capabilities"] = tuple(evidence.get("capabilities", ()))
        return EvaluationEvidence(**evidence)

    def save_evaluation(
        self, key: str, evidence: EvaluationEvidence, *, identity: dict[str, Any]
    ) -> None:
        path = self.evaluation_path(key)
        existing = self._read(path)
        serialized = asdict(evidence)
        if existing is not None:
            old = existing.get("evidence", {})
            semantic_fields = (
                "protocol_id", "protocol_version", "compile_pass", "link_pass",
                "behavioral_pass", "reason", "tests_total", "tests_passed",
            )
            if any(old.get(field) != serialized.get(field) for field in semantic_fields):
                raise ValueError(f"Evaluation cache conflict for key {key}")
            return
        self._write(path, {
            "schema": "evaluation-cache/v1",
            "key": key,
            "identity": identity,
            "evidence": serialized,
        })
