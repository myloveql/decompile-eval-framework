from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .cache_layers import LayeredCache, candidate_key, evaluation_key, generation_key
from .models import DecompileResult, EvaluationEvidence
from .plugins import create_dataset
from .reporting import read_jsonl, write_report
from .selection import SelectionManifest
from .util import safe_name


def _artifact_dir(run_dir: Path, row: dict[str, Any]) -> Path:
    configured = row.get("artifact_dir")
    if configured:
        path = Path(configured)
        if path.exists():
            return path
    return (
        run_dir / "artifacts" / safe_name(str(row["dataset_id"]))
        / safe_name(str(row["backend_id"])) / safe_name(str(row["sample_id"]))
    )


def import_run(
    run_dir: Path, cache_dir: Path, *, config: dict[str, Any] | None = None,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    manifest_path = run_dir / "manifest.json"
    results_path = run_dir / "results.jsonl"
    generations_path = run_dir / "generations.jsonl"
    records_path = results_path if results_path.exists() else generations_path
    if not manifest_path.exists() or not records_path.exists():
        raise FileNotFoundError(
            f"Run must contain manifest.json and results.jsonl or generations.jsonl: {run_dir}"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_config = manifest.get("config", {})
    backends = {row["id"]: row for row in run_config.get("decompilers", [])}
    postprocessors = run_config.get("postprocessors", ["markdown_fence"])
    cache = LayeredCache(cache_dir.resolve())
    sample_context = {}
    if config is not None:
        if base_dir is None:
            raise ValueError("base_dir is required when config is provided")
        for dataset_config in config["datasets"]:
            adapter = create_dataset(dataset_config, base_dir)
            for sample in adapter.iter_samples():
                sample_context[(sample.dataset_id, sample.sample_id)] = (
                    sample, adapter, dataset_config
                )
    imported = 0
    evaluations_imported = 0
    skipped = []
    for row in read_jsonl(records_path):
        backend_id = str(row["backend_id"])
        backend_config = backends.get(backend_id)
        artifacts = _artifact_dir(run_dir, row)
        request_path = artifacts / "request.json"
        candidate_path = artifacts / "candidate.c"
        if backend_config is None or not request_path.exists() or not candidate_path.exists():
            skipped.append({
                "dataset_id": row.get("dataset_id"),
                "sample_id": row.get("sample_id"),
                "backend_id": backend_id,
                "reason": "backend_config_or_artifact_missing",
                "artifact_dir": str(artifacts),
            })
            continue
        request = json.loads(request_path.read_text(encoding="utf-8"))
        backend_version = str(row.get("backend_version", backend_config.get("version", "unknown")))
        required_inputs = row.get(
            "backend_required_inputs", backend_config.get("required_inputs", ["assembly"])
        )
        gen_key = generation_key(request, backend_config, backend_version, required_inputs)
        raw_path = artifacts / "raw_output.txt"
        raw = raw_path.read_text(encoding="utf-8", errors="replace") if raw_path.exists() else ""
        backend_code_path = artifacts / "backend_code.c"
        backend_code = (
            backend_code_path.read_text(encoding="utf-8", errors="replace")
            if backend_code_path.exists() else raw
        )
        log_path = artifacts / "decompiler.log"
        log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        decompile_success = bool(row.get("decompile_success"))
        result = DecompileResult(
            success=decompile_success,
            raw_output=raw,
            code=backend_code,
            reason=None if decompile_success else row.get("reason") or "decompile_failed",
            log=log,
            elapsed_seconds=float(row.get("decompile_elapsed_seconds", 0.0) or 0.0),
            backend_version=backend_version,
        )
        identity = {
            "dataset_id": row["dataset_id"],
            "sample_id": row["sample_id"],
            "backend_id": backend_id,
        }
        cand_key = candidate_key(gen_key, postprocessors)
        candidate = candidate_path.read_text(encoding="utf-8", errors="replace")
        try:
            cache.save_generation(gen_key, result, identity=identity, imported_from=str(run_dir))
            actions_path = artifacts / "postprocess.json"
            actions = list(row.get("postprocess_actions", []))
            if not actions and actions_path.exists():
                actions = json.loads(actions_path.read_text(encoding="utf-8"))
            cache.save_candidate(
                cand_key,
                candidate,
                actions,
                generation_cache_key=gen_key,
                identity=identity,
                imported_from=str(run_dir),
            )
        except ValueError as error:
            skipped.append({
                **identity,
                "reason": "cache_conflict_preserved_existing",
                "detail": str(error),
                "artifact_dir": str(artifacts),
            })
            continue
        context = sample_context.get((str(row["dataset_id"]), str(row["sample_id"])))
        evaluation_path = artifacts / "evaluation.json"
        if context is not None and evaluation_path.exists():
            sample, adapter, dataset_config = context
            evidence_value = json.loads(evaluation_path.read_text(encoding="utf-8"))
            evidence_value["capabilities"] = tuple(evidence_value.get("capabilities", ()))
            evidence = EvaluationEvidence(**evidence_value)
            eval_key = evaluation_key(
                sample_content_hash=sample.content_hash,
                candidate_code=candidate,
                dataset_config=dataset_config,
                protocol_descriptor=adapter.evaluation_protocol.descriptor.to_dict(),
                protocol_config=adapter.evaluation_protocol.config,
                executor_config=config["executor"],
            )
            cache.save_evaluation(eval_key, evidence, identity={
                **identity, "candidate_key": cand_key,
            })
            evaluations_imported += 1
        imported += 1
    return {
        "run_dir": str(run_dir),
        "record_source": records_path.name,
        "cache_dir": str(cache_dir.resolve()),
        "imported": imported,
        "evaluations_imported": evaluations_imported,
        "skipped": len(skipped),
        "skipped_records": skipped,
    }


def derive_subset(
    source_run: Path, selection_path: Path, output_run: Path, *, force: bool = False
) -> dict[str, Any]:
    source_run = source_run.resolve()
    output_run = output_run.resolve()
    if output_run.exists() and any(output_run.iterdir()) and not force:
        raise FileExistsError(f"Output run is not empty: {output_run}; use --force to replace report files")
    source_manifest_path = source_run / "manifest.json"
    if not source_manifest_path.exists():
        raise FileNotFoundError(f"Missing source manifest: {source_manifest_path}")
    selection = SelectionManifest(selection_path.resolve())
    selected = {(entry.dataset_id, entry.sample_id) for entry in selection.entries}
    source_rows = read_jsonl(source_run / "results.jsonl")
    rows = [
        row for row in source_rows
        if (str(row.get("dataset_id")), str(row.get("sample_id"))) in selected
    ]
    dataset_backends: dict[str, set[str]] = {}
    for row in source_rows:
        dataset_backends.setdefault(str(row.get("dataset_id")), set()).add(
            str(row.get("backend_id"))
        )
    missing_datasets = sorted({dataset for dataset, _ in selected} - set(dataset_backends))
    if missing_datasets:
        raise ValueError(
            f"Source run contains no results for selected datasets: {', '.join(missing_datasets)}"
        )
    available_results = {
        (str(row.get("dataset_id")), str(row.get("sample_id")), str(row.get("backend_id")))
        for row in rows
    }
    expected_results = {
        (dataset, sample, backend)
        for dataset, sample in selected
        for backend in dataset_backends[dataset]
    }
    missing = sorted(expected_results - available_results)
    if missing:
        preview = ", ".join(
            f"{dataset}:{backend}:{sample}" for dataset, sample, backend in missing[:5]
        )
        raise ValueError(
            f"Source run is missing {len(missing)} selected sample/backend results: {preview}"
        )
    output_run.mkdir(parents=True, exist_ok=True)
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    derived_manifest = dict(source_manifest)
    derived_manifest["derived_from"] = str(source_run)
    derived_manifest["derivation"] = {
        "type": "selection_manifest",
        "path": str(selection.path.resolve()),
        "selection_hash": selection.selection_hash,
        "selected_sample_count": len(selected),
        "result_count": len(rows),
    }
    (output_run / "manifest.json").write_text(
        json.dumps(derived_manifest, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    with (output_run / "results.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            copied = dict(row)
            copied["derived_from_artifact_dir"] = copied.get("artifact_dir")
            handle.write(json.dumps(copied, ensure_ascii=False, default=str) + "\n")
    summary = write_report(output_run)
    return {
        "source_run": str(source_run),
        "output_run": str(output_run),
        "selection_hash": selection.selection_hash,
        "selected_samples": len(selected),
        "results": len(rows),
        "summary": summary,
    }
