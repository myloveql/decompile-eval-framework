from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import CanonicalSample
from .util import resolve_path, sha256_json


SELECTION_MANIFEST_SCHEMA = "decomp-eval-selection/v1"


@dataclass(frozen=True)
class SelectionEntry:
    dataset_id: str
    split: str
    sample_id: str
    source_group_id: str
    optimization: str
    content_hash: str

    @classmethod
    def from_sample(cls, sample: CanonicalSample) -> "SelectionEntry":
        return cls(
            dataset_id=sample.dataset_id,
            split=sample.split,
            sample_id=sample.sample_id,
            source_group_id=sample.source_group_id,
            optimization=sample.optimization,
            content_hash=sample.content_hash,
        )


def build_selection_manifest(samples: Iterable[CanonicalSample]) -> dict[str, Any]:
    entries = [asdict(SelectionEntry.from_sample(sample)) for sample in samples]
    if not entries:
        raise ValueError("Cannot create an empty selection manifest")
    keys = [(row["dataset_id"], row["sample_id"]) for row in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("Selected samples contain duplicate (dataset_id, sample_id) keys")
    return {
        "schema": SELECTION_MANIFEST_SCHEMA,
        "selection_hash": sha256_json(entries),
        "sample_count": len(entries),
        "entries": entries,
    }


class SelectionManifest:
    """Strict, content-addressed selection shared by all dataset adapters."""

    def __init__(self, path: Path):
        self.path = path
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != SELECTION_MANIFEST_SCHEMA:
            raise ValueError(
                f"Unsupported selection manifest schema in {path}: {payload.get('schema')!r}"
            )
        raw_entries = payload.get("entries")
        if not isinstance(raw_entries, list) or not raw_entries:
            raise ValueError(f"Selection manifest {path} has no entries")
        expected_hash = payload.get("selection_hash")
        actual_hash = sha256_json(raw_entries)
        if expected_hash != actual_hash:
            raise ValueError(
                f"Selection manifest hash mismatch in {path}: expected {expected_hash}, got {actual_hash}"
            )
        if payload.get("sample_count") != len(raw_entries):
            raise ValueError(f"Selection manifest sample_count is incorrect in {path}")
        self.entries = [SelectionEntry(**row) for row in raw_entries]
        self.selection_hash = actual_hash

    def filter(
        self, samples: Iterable[CanonicalSample], *, dataset_id: str
    ) -> Iterator[CanonicalSample]:
        selected = {
            entry.sample_id: entry for entry in self.entries if entry.dataset_id == dataset_id
        }
        if not selected:
            raise ValueError(
                f"Selection manifest {self.path} contains no entries for dataset {dataset_id!r}"
            )
        if len(selected) != sum(entry.dataset_id == dataset_id for entry in self.entries):
            raise ValueError(
                f"Selection manifest {self.path} contains duplicate sample IDs for dataset {dataset_id!r}"
            )
        found: set[str] = set()
        for sample in samples:
            expected = selected.get(sample.sample_id)
            if expected is None:
                continue
            actual = SelectionEntry.from_sample(sample)
            if actual != expected:
                mismatches = [
                    name
                    for name in SelectionEntry.__dataclass_fields__
                    if getattr(actual, name) != getattr(expected, name)
                ]
                raise ValueError(
                    f"Selected sample {dataset_id}:{sample.sample_id} changed fields: "
                    + ", ".join(mismatches)
                )
            found.add(sample.sample_id)
            yield sample
        missing = sorted(set(selected) - found)
        if missing:
            preview = ", ".join(missing[:5])
            suffix = " ..." if len(missing) > 5 else ""
            raise ValueError(
                f"Selection manifest {self.path} is missing {len(missing)} samples from "
                f"dataset {dataset_id!r}: {preview}{suffix}"
            )


class SelectedDatasetAdapter:
    def __init__(self, adapter: Any, manifest: SelectionManifest):
        object.__setattr__(self, "_adapter", adapter)
        object.__setattr__(self, "selection_manifest", manifest)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._adapter, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_adapter", "selection_manifest"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._adapter, name, value)

    def iter_samples(self) -> Iterable[CanonicalSample]:
        return self.selection_manifest.filter(
            self._adapter.iter_samples(), dataset_id=self._adapter.dataset_id
        )


def apply_selection(adapter: Any, config: dict[str, Any], base_dir: Path) -> Any:
    configured = config.get("selection_manifest")
    if not configured:
        return adapter
    path = resolve_path(configured, base_dir)
    return SelectedDatasetAdapter(adapter, SelectionManifest(path))
