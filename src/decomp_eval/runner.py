from __future__ import annotations

import json
import inspect
import platform
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .executor import LocalExecutor
from .cache_layers import (
    LayeredCache, candidate_key, evaluation_dataset_config, evaluation_key, generation_key,
)
from .metrics import create_metrics
from .models import DecompileResult, MetricContext
from .plugins import create_backend, create_dataset
from .postprocess import process_code
from .reporting import read_jsonl, write_report
from .util import redact, resolve_path, safe_name, sha256_json, sha256_text


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


class EvaluationRunner:
    def __init__(
        self, config: dict[str, Any], *, run_dir: Path | None = None,
        resume: bool = False, evaluate_only: bool = False, generate_only: bool = False,
    ):
        if evaluate_only and generate_only:
            raise ValueError("evaluate_only and generate_only are mutually exclusive")
        self.config = config
        configured_root = config.get("workspace_root")
        config_parent = Path(config.get("_config_path", Path.cwd())).resolve().parent
        self.base_dir = resolve_path(configured_root, config_parent) if configured_root else Path.cwd().resolve()
        output = config["output"]
        output_root = resolve_path(output["root"], self.base_dir)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = run_dir.resolve() if run_dir else output_root / f"run-{timestamp}-{config['_config_hash'][:8]}"
        self.cache_dir = resolve_path(output["cache"], self.base_dir)
        self.layered_cache = LayeredCache(self.cache_dir)
        self.resume = resume
        self.evaluate_only = evaluate_only
        self.generate_only = generate_only
        self.execution_mode = (
            "evaluate-only" if evaluate_only else "generate-only" if generate_only else "run"
        )
        executor_cfg = dict(config["executor"])
        executor_cfg.pop("type", None)
        self.executor = LocalExecutor(**executor_cfg)
        self.datasets = [(create_dataset(entry, self.base_dir), entry) for entry in config["datasets"]]
        self.backends = [(create_backend(entry, self.base_dir), entry) for entry in config["decompilers"]]
        self.metrics = create_metrics(config.get("metrics", []))
        self.postprocessors = config.get("postprocessors", ["markdown_fence"])
        self.samples_by_dataset: list[tuple[Any, dict[str, Any], list[Any]]] = []

    def load_samples(self) -> list[tuple[Any, dict[str, Any], list[Any]]]:
        if not self.samples_by_dataset:
            for adapter, cfg in self.datasets:
                samples = list(adapter.iter_samples())
                if not samples:
                    raise RuntimeError(f"Dataset {cfg['id']} selected no samples")
                self.samples_by_dataset.append((adapter, cfg, samples))
        return self.samples_by_dataset

    def _reference_cache_path(self, sample, dataset_cfg: dict[str, Any]) -> Path:
        protocol = self._protocol_for_sample(sample)
        evaluator_key = sha256_json(
            {
                "sample": sample.content_hash,
                "dataset": evaluation_dataset_config(dataset_cfg),
                "executor": self.config.get("executor"),
                "protocol": protocol.descriptor.to_dict(),
                "protocol_config": protocol.config,
            }
        )
        return self.cache_dir / "reference" / f"{evaluator_key}.json"

    def _protocol_for_sample(self, sample):
        return next(
            adapter.evaluation_protocol
            for adapter, cfg, _ in self.load_samples()
            if cfg["id"] == sample.dataset_id
        )

    def validate_datasets(self, *, force: bool = False) -> dict[str, Any]:
        self.executor.check_environment()
        records = []
        for adapter, dataset_cfg, samples in self.load_samples():
            for index, sample in enumerate(samples, 1):
                cache_path = self._reference_cache_path(sample, dataset_cfg)
                if cache_path.exists() and not force:
                    record = json.loads(cache_path.read_text(encoding="utf-8"))
                    record["cached"] = True
                else:
                    with tempfile.TemporaryDirectory(prefix="decomp_eval_ref_") as temp:
                        validation = adapter.evaluation_protocol.validate_reference(
                            sample, self.executor, Path(temp)
                        )
                    record = {
                        "dataset_id": sample.dataset_id,
                        "split": sample.split,
                        "sample_id": sample.sample_id,
                        "optimization": sample.optimization,
                        "protocol": adapter.evaluation_protocol.descriptor.to_dict(),
                        "valid": validation.valid,
                        "evidence": asdict(validation.evidence),
                        "cached": False,
                    }
                    _write_json(cache_path, record)
                records.append(record)
                print(f"[reference {len(records)}] {sample.sample_id}: {'pass' if record['valid'] else 'FAIL'}", flush=True)
        report = {
            "total": len(records),
            "valid": sum(row["valid"] for row in records),
            "invalid": sum(not row["valid"] for row in records),
            "records": records,
        }
        self.run_dir.mkdir(parents=True, exist_ok=True)
        _write_json(self.run_dir / "preflight.json", report)
        return report

    def _manifest(self) -> dict[str, Any]:
        protocols = {
            cfg["id"]: adapter.evaluation_protocol.descriptor.to_dict()
            for adapter, cfg in self.datasets
        }
        return {
            "schema_version": 2,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "framework_version": "0.6.0",
            "execution_mode": self.execution_mode,
            "config_hash": self.config["_config_hash"],
            "config": redact({key: value for key, value in self.config.items() if not key.startswith("_")}),
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "evaluation_protocols": protocols,
            "selection_manifests": self._selection_manifests(),
            "decompiler_inputs": {
                backend.backend_id: list(getattr(backend, "required_inputs", ("assembly",)))
                for backend, _ in self.backends
            },
            "denominator_policy": "all selected reference-valid samples; decompile/compile/link/test failures count as failures",
            "recompilable_definition": "object compilation and fixture linkage both succeed",
            "behavioral_definition": "all tests for the sample pass",
        }

    def _selection_manifests(self) -> dict[str, dict[str, Any]]:
        result = {}
        for adapter, cfg in self.datasets:
            selection = getattr(adapter, "selection_manifest", None)
            if selection is not None:
                result[cfg["id"]] = {
                    "path": str(selection.path.resolve()),
                    "selection_hash": selection.selection_hash,
                    "sample_count": sum(
                        entry.dataset_id == cfg["id"] for entry in selection.entries
                    ),
                }
        return result

    def run(self) -> dict[str, Any]:
        if self.generate_only:
            raise RuntimeError("Use generate() for a generate-only runner")
        self.executor.check_environment()
        if self.evaluate_only:
            self._assert_generation_cache_complete()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = self.run_dir / "manifest.json"
        if self.resume and manifest_path.exists():
            previous = json.loads(manifest_path.read_text(encoding="utf-8"))
            if previous.get("schema_version") != 2:
                raise RuntimeError(
                    "Cannot resume a pre-protocol run; start a new run directory with framework 0.2+"
                )
            if previous.get("config_hash") != self.config["_config_hash"]:
                raise RuntimeError("Cannot resume: run manifest config hash differs from the current config")
            if previous.get("selection_manifests", {}) != self._selection_manifests():
                raise RuntimeError(
                    "Cannot resume: selection manifest path, hash, or sample count changed"
                )
            expected_mode = self.execution_mode
            if previous.get("execution_mode", "run") != expected_mode:
                raise RuntimeError("Cannot resume: execution mode differs from the original run")
        else:
            _write_json(manifest_path, self._manifest())
        mode = self.config.get("preflight", {}).get("mode", "strict")
        if mode != "off":
            preflight = self.validate_datasets()
            if preflight["invalid"] and mode == "strict":
                raise RuntimeError(f"Reference preflight failed for {preflight['invalid']} samples; see preflight.json")

        results_path = self.run_dir / "results.jsonl"
        existing = read_jsonl(results_path) if self.resume else []
        completed = {
            (
                row["dataset_id"], row["backend_id"], row["sample_id"],
                row.get("protocol_id", "unknown"), row.get("protocol_version", "unknown"),
            )
            for row in existing
        }
        file_mode = "a" if self.resume else "w"
        result_count = len(existing)
        with results_path.open(file_mode, encoding="utf-8") as output:
            for backend, backend_cfg in self.backends:
                prepare_samples = []
                for adapter, _, samples in self.load_samples():
                    descriptor = adapter.evaluation_protocol.descriptor
                    for sample in samples:
                        completed_key = (
                            sample.dataset_id,
                            backend.backend_id,
                            sample.sample_id,
                            descriptor.protocol_id,
                            descriptor.version,
                        )
                        if completed_key in completed:
                            continue
                        if self._generation_cache_path(sample, backend, backend_cfg).exists():
                            continue
                        if self._missing_backend_input(sample, backend):
                            continue
                        prepare_samples.append(sample)
                if prepare_samples:
                    backend.prepare(prepare_samples)
                try:
                    for adapter, _, samples in self.load_samples():
                        descriptor = adapter.evaluation_protocol.descriptor
                        pending = [
                            sample for sample in samples
                            if (
                                sample.dataset_id, backend.backend_id, sample.sample_id,
                                descriptor.protocol_id, descriptor.version,
                            ) not in completed
                        ]
                        batch_size = max(1, int(backend_cfg.get("batch_size", 1)))
                        for offset in range(0, len(pending), batch_size):
                            batch = pending[offset : offset + batch_size]
                            uncached: list[tuple[Any, Path]] = []
                            records: list[tuple[Any, dict[str, Any]]] = []
                            for sample in batch:
                                artifact_dir = self._artifact_dir(sample, backend.backend_id)
                                if self._generation_cache_path(sample, backend, backend_cfg).exists():
                                    records.append((sample, self._evaluate_one(adapter, sample, backend, backend_cfg, artifact_dir)))
                                elif missing := self._missing_backend_input(sample, backend):
                                    records.append((sample, self._evaluate_one(
                                        adapter, sample, backend, backend_cfg, artifact_dir,
                                        decompiled_override=DecompileResult(
                                            success=False, reason=missing, backend_version=backend.version
                                        ),
                                    )))
                                else:
                                    self._prepare_request_artifacts(sample, backend, artifact_dir)
                                    uncached.append((sample, artifact_dir))
                            if uncached:
                                try:
                                    decompiled_batch = backend.decompile_many(
                                        [
                                            sample.public_request(getattr(backend, "required_inputs", ("assembly",)))
                                            for sample, _ in uncached
                                        ],
                                        [path for _, path in uncached],
                                    )
                                    if len(decompiled_batch) != len(uncached):
                                        raise ValueError("decompile_many returned a different number of results")
                                except Exception as error:
                                    decompiled_batch = [
                                        DecompileResult(success=False, reason="decompiler_exception", log=repr(error))
                                        for _ in uncached
                                    ]
                                for (sample, artifact_dir), decompiled in zip(uncached, decompiled_batch):
                                    records.append(
                                        (sample, self._evaluate_one(
                                            adapter, sample, backend, backend_cfg, artifact_dir,
                                            decompiled_override=decompiled,
                                        ))
                                    )
                            for sample, record in records:
                                output.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                                output.flush()
                                result_count += 1
                                print(
                                    f"[{result_count}] {sample.dataset_id}/{backend.backend_id}/{sample.sample_id}: "
                                    f"{record.get('reason') or 'pass'}",
                                    flush=True,
                                )
                finally:
                    backend.close()
        return write_report(self.run_dir, self.metrics)

    def generate(self) -> dict[str, Any]:
        if not self.generate_only:
            raise RuntimeError("generate() requires generate_only=True")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = self.run_dir / "manifest.json"
        if self.resume and manifest_path.exists():
            previous = json.loads(manifest_path.read_text(encoding="utf-8"))
            if previous.get("config_hash") != self.config["_config_hash"]:
                raise RuntimeError("Cannot resume: run manifest config hash differs from the current config")
            if previous.get("selection_manifests", {}) != self._selection_manifests():
                raise RuntimeError("Cannot resume: selection manifest changed")
            if previous.get("execution_mode") != "generate-only":
                raise RuntimeError("Cannot resume: execution mode differs from the original run")
        else:
            _write_json(manifest_path, self._manifest())
        records_path = self.run_dir / "generations.jsonl"
        existing = read_jsonl(records_path) if self.resume else []
        completed = {
            (row["dataset_id"], row["backend_id"], row["sample_id"]) for row in existing
        }
        count = len(existing)
        with records_path.open("a" if self.resume else "w", encoding="utf-8") as output:
            for backend, backend_cfg in self.backends:
                prepare_samples = [
                    sample
                    for _, _, samples in self.load_samples()
                    for sample in samples
                    if (sample.dataset_id, backend.backend_id, sample.sample_id) not in completed
                    and not self._generation_cache_path(sample, backend, backend_cfg).exists()
                    and not self._missing_backend_input(sample, backend)
                ]
                if prepare_samples:
                    backend.prepare(prepare_samples)
                try:
                    for adapter, _, samples in self.load_samples():
                        pending = [
                            sample for sample in samples
                            if (sample.dataset_id, backend.backend_id, sample.sample_id) not in completed
                        ]
                        batch_size = max(1, int(backend_cfg.get("batch_size", 1)))
                        for offset in range(0, len(pending), batch_size):
                            batch = pending[offset : offset + batch_size]
                            uncached: list[tuple[Any, Path]] = []
                            records: list[tuple[Any, dict[str, Any]]] = []
                            for sample in batch:
                                artifact_dir = self._artifact_dir(sample, backend.backend_id)
                                if self._generation_cache_path(sample, backend, backend_cfg).exists():
                                    records.append((sample, self._evaluate_one(
                                        adapter, sample, backend, backend_cfg, artifact_dir,
                                        generation_only=True,
                                    )))
                                elif missing := self._missing_backend_input(sample, backend):
                                    records.append((sample, self._evaluate_one(
                                        adapter, sample, backend, backend_cfg, artifact_dir,
                                        decompiled_override=DecompileResult(
                                            success=False, reason=missing,
                                            backend_version=backend.version,
                                        ),
                                        generation_only=True,
                                    )))
                                else:
                                    self._prepare_request_artifacts(sample, backend, artifact_dir)
                                    uncached.append((sample, artifact_dir))
                            if uncached:
                                try:
                                    values = backend.decompile_many(
                                        [
                                            sample.public_request(getattr(
                                                backend, "required_inputs", ("assembly",)
                                            ))
                                            for sample, _ in uncached
                                        ],
                                        [path for _, path in uncached],
                                    )
                                    if len(values) != len(uncached):
                                        raise ValueError(
                                            "decompile_many returned a different number of results"
                                        )
                                except Exception as error:
                                    values = [
                                        DecompileResult(
                                            success=False, reason="decompiler_exception", log=repr(error)
                                        )
                                        for _ in uncached
                                    ]
                                for (sample, artifact_dir), decompiled in zip(uncached, values):
                                    records.append((sample, self._evaluate_one(
                                        adapter, sample, backend, backend_cfg, artifact_dir,
                                        decompiled_override=decompiled,
                                        generation_only=True,
                                    )))
                            for sample, record in records:
                                output.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                                output.flush()
                                count += 1
                                print(
                                    f"[generation {count}] {sample.dataset_id}/"
                                    f"{backend.backend_id}/{sample.sample_id}: "
                                    f"{record.get('reason') or 'pass'}",
                                    flush=True,
                                )
                finally:
                    backend.close()
        rows = read_jsonl(records_path)
        summary = {
            "total": len(rows),
            "decompile_success": sum(bool(row.get("decompile_success")) for row in rows),
            "candidate_available": sum(bool(row.get("candidate_available")) for row in rows),
            "generation_cache_hits": sum(bool(row.get("generation_cache_hit")) for row in rows),
        }
        _write_json(self.run_dir / "generation_summary.json", summary)
        return summary

    def _assert_generation_cache_complete(self) -> None:
        missing = []
        for backend, backend_cfg in self.backends:
            for _, _, samples in self.load_samples():
                for sample in samples:
                    if not self._generation_cache_path(sample, backend, backend_cfg).exists():
                        missing.append(
                            f"{sample.dataset_id}/{backend.backend_id}/{sample.sample_id}"
                        )
        if missing:
            preview = ", ".join(missing[:5])
            suffix = " ..." if len(missing) > 5 else ""
            raise RuntimeError(
                f"Evaluate-only mode is missing {len(missing)} generation cache entries: "
                f"{preview}{suffix}. Import historical runs first or use the normal run command."
            )

    def _artifact_dir(self, sample, backend_id: str) -> Path:
        return (
            self.run_dir / "artifacts" / safe_name(sample.dataset_id) /
            safe_name(backend_id) / safe_name(sample.sample_id)
        )

    @staticmethod
    def _missing_backend_input(sample, backend) -> str | None:
        for input_kind in getattr(backend, "required_inputs", ("assembly",)):
            if input_kind == "assembly" and not sample.assembly.text.strip():
                return "assembly_missing"
            if input_kind == "binary" and (sample.binary is None or not sample.binary.path):
                return "binary_missing"
            if input_kind == "pseudocode" and (
                sample.pseudocode is None or not sample.pseudocode.text.strip()
            ):
                return "pseudocode_missing"
            if input_kind == "compile_context" and sample.compile_context is None:
                return "compile_context_missing"
        return None

    def _generation_cache_key(self, sample, backend, backend_cfg: dict[str, Any]) -> str:
        request = sample.public_request(getattr(backend, "required_inputs", ("assembly",)))
        return generation_key(
            request,
            backend_cfg,
            getattr(backend, "version", "unknown"),
            getattr(backend, "required_inputs", ("assembly",)),
        )

    def _generation_cache_path(self, sample, backend, backend_cfg: dict[str, Any]) -> Path:
        return self.layered_cache.generation_path(
            self._generation_cache_key(sample, backend, backend_cfg)
        )

    def _prepare_request_artifacts(self, sample, backend, artifact_dir: Path) -> None:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        request = sample.public_request(getattr(backend, "required_inputs", ("assembly",)))
        (artifact_dir / "assembly.s").write_text(request.assembly.text, encoding="utf-8")
        (artifact_dir / "pseudocode.c").write_text(
            request.pseudocode.text if request.pseudocode else "", encoding="utf-8"
        )
        _write_json(artifact_dir / "request.json", request.to_dict())

    def _evaluate_one(
        self, adapter, sample, backend, backend_cfg, artifact_dir: Path,
        decompiled_override: DecompileResult | None = None,
        generation_only: bool = False,
    ) -> dict[str, Any]:
        self._prepare_request_artifacts(sample, backend, artifact_dir)
        request = sample.public_request(getattr(backend, "required_inputs", ("assembly",)))
        started = time.perf_counter()
        generation_cache_key = self._generation_cache_key(sample, backend, backend_cfg)
        decompiled = self.layered_cache.load_generation(generation_cache_key)
        generation_cache_hit = decompiled is not None
        if decompiled is not None:
            pass
        elif decompiled_override is not None:
            decompiled = decompiled_override
        else:
            try:
                decompiled = backend.decompile(request, artifact_dir)
            except Exception as error:
                decompiled = DecompileResult(success=False, reason="decompiler_exception", log=repr(error))
        if not generation_cache_hit:
            self.layered_cache.save_generation(
                generation_cache_key,
                decompiled,
                identity={
                    "dataset_id": sample.dataset_id,
                    "sample_id": sample.sample_id,
                    "backend_id": backend.backend_id,
                },
            )
        raw_output = decompiled.raw_output or decompiled.code
        (artifact_dir / "raw_output.txt").write_text(raw_output, encoding="utf-8")
        (artifact_dir / "backend_code.c").write_text(decompiled.code, encoding="utf-8")
        (artifact_dir / "decompiler.log").write_text(decompiled.log, encoding="utf-8")

        candidate_cache_key = candidate_key(generation_cache_key, self.postprocessors)
        cached_candidate = self.layered_cache.load_candidate(candidate_cache_key)
        candidate_cache_hit = cached_candidate is not None
        if cached_candidate is not None:
            candidate = str(cached_candidate.get("code", ""))
            processed_actions = list(cached_candidate.get("actions", []))
        else:
            processed_actions: list[dict[str, Any]] = []
            process_input = decompiled.code or raw_output
            if decompiled.success and process_input.strip():
                processed = process_code(process_input, sample, self.postprocessors)
                candidate = processed.code
                processed_actions = processed.actions
            else:
                candidate = ""
            self.layered_cache.save_candidate(
                candidate_cache_key,
                candidate,
                processed_actions,
                generation_cache_key=generation_cache_key,
                identity={
                    "dataset_id": sample.dataset_id,
                    "sample_id": sample.sample_id,
                    "backend_id": backend.backend_id,
                },
            )
        (artifact_dir / "candidate.c").write_text(candidate, encoding="utf-8")
        _write_json(artifact_dir / "postprocess.json", processed_actions)

        if generation_only:
            return {
                "dataset_id": sample.dataset_id,
                "split": sample.split,
                "sample_id": sample.sample_id,
                "source_group_id": sample.source_group_id,
                "function_name": sample.function_name,
                "language": sample.language,
                "optimization": sample.optimization,
                "backend_id": backend.backend_id,
                "backend_version": decompiled.backend_version or backend.version,
                "backend_required_inputs": list(getattr(backend, "required_inputs", ("assembly",))),
                "decompile_success": bool(decompiled.success),
                "candidate_available": bool(candidate.strip()),
                "reason": decompiled.reason if not decompiled.success else None,
                "generation_key": generation_cache_key,
                "candidate_key": candidate_cache_key,
                "generation_cache_hit": generation_cache_hit,
                "candidate_cache_hit": candidate_cache_hit,
                "artifact_dir": str(artifact_dir),
            }

        evaluation_cache_hit = False
        evaluation_cache_key = None
        if not decompiled.success or not candidate:
            evidence = adapter.evaluation_protocol.failure_evidence(
                decompiled.reason or "decompile_empty_output", stage="decompile"
            )
            decompile_success = False
        else:
            decompile_success = True
            dataset_cfg = next(
                cfg for _, cfg, _ in self.load_samples() if cfg["id"] == sample.dataset_id
            )
            evaluation_cache_key = evaluation_key(
                sample_content_hash=sample.content_hash,
                candidate_code=candidate,
                dataset_config=dataset_cfg,
                protocol_descriptor=adapter.evaluation_protocol.descriptor.to_dict(),
                protocol_config=adapter.evaluation_protocol.config,
                executor_config=self.config["executor"],
            )
            evidence = self.layered_cache.load_evaluation(evaluation_cache_key)
            evaluation_cache_hit = evidence is not None
            if evidence is None:
                try:
                    evidence = adapter.evaluation_protocol.evaluate_candidate(
                        sample, candidate, self.executor, artifact_dir / "evaluation"
                    )
                except Exception as error:
                    evidence = adapter.evaluation_protocol.failure_evidence(
                        "evaluator_exception", error=repr(error)
                    )
                self.layered_cache.save_evaluation(
                    evaluation_cache_key,
                    evidence,
                    identity={
                        "dataset_id": sample.dataset_id,
                        "sample_id": sample.sample_id,
                        "candidate_key": candidate_cache_key,
                    },
                )
        _write_json(artifact_dir / "evaluation.json", asdict(evidence))
        metric_context = MetricContext(
            candidate_code=candidate,
            candidate_sha256=sha256_text(candidate),
            artifact_dir=str(artifact_dir),
            generation_key=generation_cache_key,
            candidate_key=candidate_cache_key,
            evaluation_key=evaluation_cache_key,
        )
        metric_values = {
            metric.name: self._evaluate_metric(metric, sample, evidence, metric_context)
            for metric in self.metrics
        }
        record = {
            "dataset_id": sample.dataset_id,
            "split": sample.split,
            "sample_id": sample.sample_id,
            "sample_content_hash": sample.content_hash,
            "source_group_id": sample.source_group_id,
            "function_name": sample.function_name,
            "language": sample.language,
            "optimization": sample.optimization,
            "assembly_view": sample.assembly.view,
            "pseudocode_view": sample.pseudocode.view if sample.pseudocode else None,
            "protocol_id": evidence.protocol_id,
            "protocol_version": evidence.protocol_version,
            "protocol_capabilities": list(evidence.capabilities),
            "protocol_descriptor": adapter.evaluation_protocol.descriptor.to_dict(),
            "backend_id": backend.backend_id,
            "backend_version": decompiled.backend_version or getattr(backend, "version", "unknown"),
            "backend_required_inputs": list(getattr(backend, "required_inputs", ("assembly",))),
            "decompile_success": decompile_success,
            "compile_pass": evidence.compile_pass,
            "link_pass": evidence.link_pass,
            "recompilable": evidence.recompilable,
            "behavioral_pass": evidence.behavioral_pass,
            "reason": evidence.reason,
            "tests_total": evidence.tests_total,
            "tests_passed": evidence.tests_passed,
            "metrics": metric_values,
            "postprocess_actions": processed_actions,
            "decompile_elapsed_seconds": decompiled.elapsed_seconds,
            "evaluation_elapsed_seconds": evidence.elapsed_seconds,
            "elapsed_seconds": time.perf_counter() - started,
            "artifact_dir": str(artifact_dir),
            "generation_key": generation_cache_key,
            "candidate_key": candidate_cache_key,
            "candidate_sha256": metric_context.candidate_sha256,
            "evaluation_key": evaluation_cache_key,
            "generation_cache_hit": generation_cache_hit,
            "candidate_cache_hit": candidate_cache_hit,
            "evaluation_cache_hit": evaluation_cache_hit,
            "cache_hit": generation_cache_hit and candidate_cache_hit and (
                evaluation_cache_hit or not decompile_success
            ),
        }
        return record

    @staticmethod
    def _evaluate_metric(metric, sample, evidence, context: MetricContext):
        parameters = inspect.signature(metric.evaluate).parameters
        if "context" in parameters:
            return metric.evaluate(sample, evidence, context=context)
        return metric.evaluate(sample, evidence)
