from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DIMENSIONS = (
    "dataset_id", "backend_id", "protocol_id", "protocol_version",
    "split", "language", "optimization",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _metric_names(values: list[dict[str, Any]]) -> list[str]:
    names = {"decompile_success", "recompilable", "behavioral_pass"}
    for row in values:
        names.update(row.get("metrics", {}).keys())
    return sorted(names)


def _metric_value(row: dict[str, Any], metric: str):
    return row.get("metrics", {}).get(metric, row.get(metric))


def _default_aggregate(values: list[Any]) -> dict[str, Any]:
    eligible = [value for value in values if value is not None]
    if not eligible:
        return {"eligible": 0, "passed": 0, "rate": 0.0}
    if all(isinstance(value, bool) for value in eligible):
        passed = sum(eligible)
        return {"eligible": len(eligible), "passed": passed, "rate": passed / len(eligible)}
    numeric = [float(value) for value in eligible if isinstance(value, (int, float))]
    return {"eligible": len(numeric), "mean": sum(numeric) / len(numeric) if numeric else None}


def _aggregate(rows: Iterable[dict[str, Any]], metrics: list[Any] | None = None) -> dict[str, Any]:
    values = list(rows)
    total = len(values)
    result: dict[str, Any] = {"total": total}
    metric_map = {metric.name: metric for metric in (metrics or [])}
    for metric_name in _metric_names(values):
        metric_values = [_metric_value(row, metric_name) for row in values]
        metric = metric_map.get(metric_name)
        aggregated = metric.aggregate(metric_values) if metric and hasattr(metric, "aggregate") else _default_aggregate(metric_values)
        for key, value in aggregated.items():
            result[f"{metric_name}_{key}"] = value
    result["failure_reasons"] = dict(sorted(Counter(row.get("reason") or "pass" for row in values).items()))
    return result


def build_summary(rows: list[dict[str, Any]], metrics: list[Any] | None = None) -> dict[str, Any]:
    by_all: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    by_opt: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    overall: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_all[tuple(str(row.get(key, "")) for key in DIMENSIONS)].append(row)
        protocol = (str(row.get("protocol_id", "unknown")), str(row.get("protocol_version", "unknown")))
        by_opt[(row["dataset_id"], row["backend_id"], *protocol, row["optimization"])].append(row)
        overall[(row["dataset_id"], row["backend_id"], *protocol)].append(row)

    def records(groups, names):
        output = []
        for key, values in sorted(groups.items()):
            output.append({**dict(zip(names, key)), **_aggregate(values, metrics)})
        return output

    return {
        "schema_version": 2,
        "total_results": len(rows),
        "by_dimensions": records(by_all, DIMENSIONS),
        "by_optimization": records(
            by_opt, ("dataset_id", "backend_id", "protocol_id", "protocol_version", "optimization")
        ),
        "overall": records(
            overall, ("dataset_id", "backend_id", "protocol_id", "protocol_version")
        ),
    }


def write_report(run_dir: Path, metrics: list[Any] | None = None) -> dict[str, Any]:
    rows = read_jsonl(run_dir / "results.jsonl")
    summary = build_summary(rows, metrics)
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    csv_rows = summary["by_dimensions"]
    with (run_dir / "summary.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [key for key in csv_rows[0].keys() if key != "failure_reasons"] if csv_rows else list(DIMENSIONS)
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_rows)
    return summary
