from __future__ import annotations

from typing import Any

from .models import CanonicalSample, EvaluationEvidence
from .util import load_object


class RecompilableMetric:
    name = "recompilable"

    def evaluate(self, sample: CanonicalSample, evidence: EvaluationEvidence) -> bool:
        return evidence.recompilable

    def aggregate(self, values):
        eligible = [bool(value) for value in values if value is not None]
        passed = sum(eligible)
        return {"eligible": len(eligible), "passed": passed, "rate": passed / len(eligible) if eligible else 0.0}


class BehavioralPassMetric:
    name = "behavioral_pass"

    def evaluate(self, sample: CanonicalSample, evidence: EvaluationEvidence) -> bool:
        return evidence.behavioral_pass

    def aggregate(self, values):
        eligible = [bool(value) for value in values if value is not None]
        passed = sum(eligible)
        return {"eligible": len(eligible), "passed": passed, "rate": passed / len(eligible) if eligible else 0.0}


BUILTIN_METRICS = {
    "recompilable": RecompilableMetric,
    "behavioral_pass": BehavioralPassMetric,
}


def create_metrics(configs: list[str | dict[str, Any]]):
    metrics = []
    for entry in configs:
        cfg = {"type": entry} if isinstance(entry, str) else dict(entry)
        kind = cfg.pop("type")
        factory = BUILTIN_METRICS.get(kind) or load_object(kind)
        metric = factory(**cfg) if isinstance(factory, type) else factory
        metrics.append(metric)
    return metrics
