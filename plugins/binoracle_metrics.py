from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class _MetadataNumberMetric:
    field = ""
    name = ""

    def evaluate(self, sample, evidence, *, context=None):
        if context is None:
            return None
        path = Path(context.artifact_dir) / "binoracle_metadata.json"
        if not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8")).get(self.field)
        return float(value) if isinstance(value, (int, float)) else None

    def aggregate(self, values: list[bool | float | None]) -> dict[str, Any]:
        eligible = [float(value) for value in values if value is not None]
        return {
            "eligible": len(eligible),
            "sum": sum(eligible),
            "mean": sum(eligible) / len(eligible) if eligible else 0.0,
            "min": min(eligible) if eligible else None,
            "max": max(eligible) if eligible else None,
        }


class _MetadataBooleanMetric(_MetadataNumberMetric):
    def evaluate(self, sample, evidence, *, context=None):
        if context is None:
            return None
        path = Path(context.artifact_dir) / "binoracle_metadata.json"
        if not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8")).get(self.field, False)
        return 1.0 if value is True else 0.0


class GeneratedTestCountMetric(_MetadataNumberMetric):
    field = "generated_tests"
    name = "binoracle_generated_tests"


class ExecutionCountMetric(_MetadataNumberMetric):
    field = "executions"
    name = "binoracle_executions"


class CounterexampleCountMetric(_MetadataNumberMetric):
    field = "counterexamples"
    name = "binoracle_counterexamples"


class RepairIterationCountMetric(_MetadataNumberMetric):
    field = "repair_iterations"
    name = "binoracle_repair_iterations"


class HarnessFrozenMetric(_MetadataBooleanMetric):
    field = "harness_frozen"
    name = "binoracle_harness_frozen"


class CandidateCompileMetric(_MetadataBooleanMetric):
    field = "candidate_compile"
    name = "binoracle_candidate_compile"


class CandidateLinkMetric(_MetadataBooleanMetric):
    field = "candidate_link"
    name = "binoracle_candidate_link"


class DifferentialPassMetric(_MetadataBooleanMetric):
    field = "differential_pass"
    name = "binoracle_differential_pass"
