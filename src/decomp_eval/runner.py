from __future__ import annotations

import json
import platform
import shutil
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .executor import LocalExecutor
from .metrics import create_metrics
from .models import DecompileResult
from .plugins import create_backend, create_dataset
from .postprocess import process_code
from .reporting import read_jsonl, write_report
from .util import redact, resolve_path, safe_name, sha256_json


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


class EvaluationRunner:
    def __init__(self, config: dict[str, Any], *, run_dir: Path | None = None, resume: bool = False):
        self.config = config
        configured_root = config.get("workspace_root")
        config_parent = Path(config.get("_config_path", Path.cwd())).resolve().parent
        self.base_dir = resolve_path(configured_root, config_parent) if configured_root else Path.cwd().resolve()
        output = config["output"]
        output_root = resolve_path(output["root"], self.base_dir)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = run_dir.resolve() if run_dir else output_root / f"run-{timestamp}-{config['_config_hash'][:8]}"
        self.cache_dir = resolve_path(output["cache"], self.base_dir)
        self.resume = resume
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
                "dataset": dataset_cfg,
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

    def _result_cache_key(self, sample, backend_cfg: dict[str, Any]) -> str:
        protocol = self._protocol_for_sample(sample)
        backend = next(item for item, cfg in self.backends if cfg is backend_cfg)
        return sha256_json(
            {
                "sample_hash": sample.content_hash,
                "assembly_view": sample.assembly.view,
                "pseudocode_view": sample.pseudocode.view if sample.pseudocode else None,
                "pseudocode_sha256": sample.pseudocode.sha256 if sample.pseudocode else None,
                "backend": backend_cfg,
                "backend_version": backend.version,
                "backend_required_inputs": list(
                    getattr(backend, "required_inputs", ("assembly",))
                ),
                "postprocessors": self.postprocessors,
                "executor": self.config["executor"],
                "dataset_evaluation": next(cfg for _, cfg, _ in self.load_samples() if cfg["id"] == sample.dataset_id),
                "protocol": protocol.descriptor.to_dict(),
                "protocol_config": protocol.config,
            }
        )

    def _manifest(self) -> dict[str, Any]:
        protocols = {
            cfg["id"]: adapter.evaluation_protocol.descriptor.to_dict()
            for adapter, cfg in self.datasets
        }
        return {
            "schema_version": 2,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "framework_version": "0.5.0",
            "config_hash": self.config["_config_hash"],
            "config": redact({key: value for key, value in self.config.items() if not key.startswith("_")}),
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "evaluation_protocols": protocols,
            "decompiler_inputs": {
                backend.backend_id: list(getattr(backend, "required_inputs", ("assembly",)))
                for backend, _ in self.backends
            },
            "denominator_policy": "all selected reference-valid samples; decompile/compile/link/test failures count as failures",
            "recompilable_definition": "object compilation and fixture linkage both succeed",
            "behavioral_definition": "all tests for the sample pass",
        }

    def run(self) -> dict[str, Any]:
        self.executor.check_environment()
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
                        if self._result_cache_path(sample, backend_cfg).exists():
                            continue
                        if self._missing_backend_input(sample, backend):
                            continue
                        prepare_samples.append(sample)
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
                                cache_path = self._result_cache_path(sample, backend_cfg)
                                if cache_path.exists():
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

    def _result_cache_path(self, sample, backend_cfg: dict[str, Any]) -> Path:
        return self.cache_dir / "results" / f"{self._result_cache_key(sample, backend_cfg)}.json"

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
    ) -> dict[str, Any]:
        cache_key = self._result_cache_key(sample, backend_cfg)
        cache_path = self._result_cache_path(sample, backend_cfg)
        if cache_path.exists():
            record = json.loads(cache_path.read_text(encoding="utf-8"))
            record["cache_hit"] = True
            record["artifact_dir"] = str(artifact_dir)
            self._prepare_request_artifacts(sample, backend, artifact_dir)
            cached_artifacts = self.cache_dir / "artifacts" / cache_key
            if cached_artifacts.exists():
                for source in cached_artifacts.iterdir():
                    if source.is_file():
                        shutil.copy2(source, artifact_dir / source.name)
            _write_json(artifact_dir / "cache_hit.json", {"cache_key": cache_key, "cached_record": str(cache_path)})
            return record

        self._prepare_request_artifacts(sample, backend, artifact_dir)
        request = sample.public_request(getattr(backend, "required_inputs", ("assembly",)))
        started = time.perf_counter()
        if decompiled_override is not None:
            decompiled = decompiled_override
        else:
            try:
                decompiled = backend.decompile(request, artifact_dir)
            except Exception as error:
                decompiled = DecompileResult(success=False, reason="decompiler_exception", log=repr(error))
        raw_output = decompiled.raw_output or decompiled.code
        (artifact_dir / "raw_output.txt").write_text(raw_output, encoding="utf-8")
        (artifact_dir / "decompiler.log").write_text(decompiled.log, encoding="utf-8")

        processed_actions: list[dict[str, Any]] = []
        process_input = decompiled.code or raw_output
        if decompiled.success and process_input.strip():
            processed = process_code(process_input, sample, self.postprocessors)
            candidate = processed.code
            processed_actions = processed.actions
        else:
            candidate = ""
        (artifact_dir / "candidate.c").write_text(candidate, encoding="utf-8")
        _write_json(artifact_dir / "postprocess.json", processed_actions)

        if not decompiled.success or not candidate:
            evidence = adapter.evaluation_protocol.failure_evidence(
                decompiled.reason or "decompile_empty_output", stage="decompile"
            )
            decompile_success = False
        else:
            decompile_success = True
            try:
                evidence = adapter.evaluation_protocol.evaluate_candidate(
                    sample, candidate, self.executor, artifact_dir / "evaluation"
                )
            except Exception as error:
                evidence = adapter.evaluation_protocol.failure_evidence(
                    "evaluator_exception", error=repr(error)
                )
        _write_json(artifact_dir / "evaluation.json", asdict(evidence))
        metric_values = {metric.name: metric.evaluate(sample, evidence) for metric in self.metrics}
        record = {
            "dataset_id": sample.dataset_id,
            "split": sample.split,
            "sample_id": sample.sample_id,
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
            "cache_key": cache_key,
            "cache_hit": False,
        }
        _write_json(cache_path, record)
        cached_artifacts = self.cache_dir / "artifacts" / cache_key
        cached_artifacts.mkdir(parents=True, exist_ok=True)
        for name in (
            "assembly.s", "pseudocode.c", "request.json", "raw_output.txt", "candidate.c", "decompiler.log",
            "postprocess.json", "evaluation.json", "backend_output.c",
            "ghidra.stdout.log", "ghidra.stderr.log",
            "model_prompt.txt", "response_metadata.json",
            "sk2_pseudocode_normalized.c", "sk2_struct_prompt.txt",
            "sk2_struct_output.c", "sk2_ident_prompt.txt", "sk2_ident_output.c",
            "sk2_final_output.c", "sk2_metadata.json",
            "sccdec_first_messages.json", "sccdec_first_raw.txt",
            "sccdec_first_candidate.c", "sccdec_self_context.s",
            "sccdec_second_messages.json", "sccdec_second_raw.txt",
            "sccdec_final_candidate.c", "sccdec_metadata.json",
        ):
            source = artifact_dir / name
            if source.exists():
                shutil.copy2(source, cached_artifacts / name)
        return record
