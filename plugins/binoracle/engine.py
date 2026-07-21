from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .active_probes import generate_failure_directed_probes, should_stop_active_probing
from .ambiguity import equivalent_if_no_disagreement, generate_discriminative_probes
from .auditor import (
    AuditThresholds,
    audit_contracts,
    freeze_harness_manifest,
)
from .capability import assess_capability
from .holdout import commit_holdout
from .resolution import HarnessResolutionState, ResolutionBudget, ResolutionStatus
from .binary_facts import extract_binary_facts
from .candidate import CandidateCompiler
from .candidates import generate_contract_candidates
from .contract import infer_contract
from .contract_v2 import ContractGraphV2, ContractValidationError
from .counterexamples import build_evidence_package, minimize_counterexample
from .differential import compare_observations
from .ir import parse_assembly
from .probes import ProbeCase, generate_probe_plan, score_contract
from .protocol import InputCase, jsonl
from .repair import (
    DeterministicRepairer,
    HybridRepairer,
    OpenAIRepairer,
    RepairBudget,
    RepairRequest,
    RepairState,
    validate_transition,
)
from .runtime import (
    ABIRunner,
    KnownContractManifest,
    RunnerBuild,
    RunnerError,
    UnsupportedSample,
)
from .schemas import ObservationPolicy
from .taint import analyze_taint


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(jsonl(values), encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _probe_from_record(
    record: dict[str, Any],
    contract: ContractGraphV2,
    runner_contract,
) -> ProbeCase:
    """Reconstruct a ProbeCase from a frozen probe_plan.jsonl record.

    The frozen record carries the full InputCase payload, so re-deriving the
    probe from the seed would risk divergence whenever the probe generator
    changes. Reading back the record keeps the differential replay pinned to
    the exact artefact committed by the harness manifest.
    """

    input_record = dict(record.get("input_case") or {})
    input_case = InputCase.from_dict(input_record, contract=runner_contract)
    return ProbeCase(
        probe_id=str(record.get("probe_id", "")),
        stability_group=str(record.get("stability_group", "")),
        repetition=int(record.get("repetition", 0)),
        purpose=str(record.get("purpose", "")),
        expected_safe=bool(record.get("expected_safe", True)),
        input_case=input_case,
    )


@dataclass(frozen=True)
class BinOracleResult:
    candidate_code: str
    summary: str
    metadata: dict[str, Any]


class BinOracleEngine:
    """Static audit plus the V1 known-contract original-binary query sprint."""

    version = "binoracle-engine-v4-phase4"

    def __init__(self, config: dict[str, Any]):
        self.config = dict(config)
        self.require_relocatable = bool(config.get("require_relocatable", True))
        self.abi = str(config.get("abi", "sysv-x86_64"))
        if self.abi != "sysv-x86_64":
            raise ValueError("BinOracle V1 supports abi=sysv-x86_64")
        self.mode = str(config.get("mode", "static_passthrough"))
        if self.mode not in {
            "static_passthrough",
            "dynamic_audit",
            "contract_probe",
            "contract_audit",
            "differential",
            "dynamic_repair",
        }:
            raise ValueError(
                "BinOracle supports static_passthrough, dynamic_audit, contract_probe, "
                "contract_audit, differential, and dynamic_repair"
            )
        self.max_contract_candidates = int(config.get("max_contract_candidates", 4))
        if not 1 <= self.max_contract_candidates <= 16:
            raise ValueError("max_contract_candidates must be between 1 and 16")
        self.probe_seed = int(config.get("probe_seed", 0))
        self.probe_repetitions = int(config.get("probe_repetitions", 2))
        self.probe_executions_per_contract = int(
            config.get("probe_executions_per_contract", 32)
        )
        if self.probe_repetitions <= 0:
            raise ValueError("probe_repetitions must be positive")
        if self.probe_executions_per_contract <= 0:
            raise ValueError("probe_executions_per_contract must be positive")
        self.audit_thresholds = AuditThresholds.from_config(config)
        self.resolution_max_rounds = int(config.get("resolution_max_rounds", 3))
        self.holdout_executions = int(config.get("holdout_executions", 8))
        if self.resolution_max_rounds < 0 or self.holdout_executions <= 0:
            raise ValueError("resolution and holdout execution limits must be positive")
        self.runner = ABIRunner(config)
        self.candidate_compiler = CandidateCompiler(config)
        self.minimize_counterexamples = bool(config.get("minimize_counterexamples", True))
        self.max_minimized_counterexamples = int(
            config.get("max_minimized_counterexamples", 3)
        )
        self.max_minimization_attempts = int(config.get("max_minimization_attempts", 8))
        if self.max_minimized_counterexamples < 0 or self.max_minimization_attempts < 0:
            raise ValueError("counterexample minimization limits must be non-negative")
        self.max_repair_iterations = int(config.get("max_repair_iterations", 3))
        if self.max_repair_iterations < 0:
            raise ValueError("max_repair_iterations must be non-negative")
        self.max_repair_model_calls = int(config.get("max_repair_model_calls", 0))
        self.max_repair_tokens = int(config.get("max_repair_tokens", 0))
        if min(self.max_repair_model_calls, self.max_repair_tokens) < 0:
            raise ValueError("repair model budgets must be non-negative")
        repairer_kind = str(config.get("repairer", "deterministic"))
        deterministic = DeterministicRepairer()
        if repairer_kind == "deterministic":
            self.repairer = deterministic
        elif repairer_kind in {"openai", "hybrid"}:
            model_repairer = OpenAIRepairer(
                model=str(config.get("repair_model", "gpt-5.6-terra")),
                max_output_tokens=int(config.get("repair_max_output_tokens", 4096)),
                reasoning_effort=str(config.get("repair_reasoning_effort", "medium")),
            )
            self.repairer = (
                model_repairer
                if repairer_kind == "openai"
                else HybridRepairer(deterministic, model_repairer)
            )
        else:
            raise ValueError("repairer must be deterministic, openai, or hybrid")
        self.repairer_kind = repairer_kind
        self.repair_resume = bool(config.get("repair_resume", True))
        self.contract_manifest = KnownContractManifest(config) if self.mode == "dynamic_audit" else None

    def prepare(self) -> None:
        if self.mode in {
            "dynamic_audit",
            "contract_probe",
            "contract_audit",
            "differential",
            "dynamic_repair",
        }:
            self.runner.prepare()

    def _write_binary_artifacts(self, stage_dir: Path, facts) -> None:
        _write_json(stage_dir / "binary_facts.json", facts.to_dict())
        _write_json(stage_dir / "symbols.json", list(facts.symbols))
        _write_json(stage_dir / "relocations.json", list(facts.relocations))
        _write_json(stage_dir / "dependencies.json", list(facts.dependencies))

    def _static_run(
        self,
        *,
        facts,
        initial_code: str,
        assembly: str,
        assembly_syntax: str,
        optimization: str,
        sample_id: str,
        artifact_dir: Path,
        stage_dir: Path,
        started: float,
    ) -> BinOracleResult:
        instructions = parse_assembly(assembly, syntax=assembly_syntax)
        taint = analyze_taint(instructions)
        _write_jsonl(
            stage_dir / "normalized_ir.jsonl",
            [item.to_dict() for item in instructions],
        )
        _write_jsonl(stage_dir / "taint_trace.jsonl", list(taint.trace))
        _write_json(stage_dir / "taint_analysis.json", taint.to_dict())
        legacy_contract = infer_contract(assembly, abi=self.abi)
        candidates = generate_contract_candidates(
            taint,
            sample_id=sample_id,
            abi=self.abi,
            globals=facts.global_objects,
            dependencies=facts.dependencies,
            max_candidates=self.max_contract_candidates,
        )
        contract = candidates[0]
        policy = ObservationPolicy(
            compare_return=False,
            compare_coverage=False,
            rationale=(
                "standalone static analysis cannot distinguish a source return from void RAX residue",
                "automatic return hypotheses are not comparable until dynamic contract audit",
                "void_or_unknown functions are evaluated through memory/global/process effects",
            ),
        )
        _write_json(
            stage_dir / "contract_candidates.json",
            [item.to_dict() for item in candidates],
        )
        _write_json(stage_dir / "selected_contract.json", contract.to_dict())
        _write_json(
            stage_dir / "contract_scores.json",
            [
                {
                    "rank": index,
                    "contract_id": item.contract_id,
                    "static_score": item.confidence,
                    "status": "static_unreviewed",
                }
                for index, item in enumerate(candidates)
            ],
        )
        _write_json(stage_dir / "observation_policy.json", policy.to_dict())
        metadata = {
            "schema_version": 1,
            "engine_version": self.version,
            "mode": self.mode,
            "sample_id": sample_id,
            "optimization": optimization,
            "selected_contract": contract.contract_id,
            "contract_schema": contract.to_dict()["schema_version"],
            "contract_hash": contract.content_hash,
            "contract_confidence": contract.confidence,
            "contract_candidates": len(candidates),
            "contract_selection_status": "static_unreviewed",
            "argument_count": len(contract.arguments),
            "pointer_candidate_count": sum(
                item.kind_candidates[0] == "pointer" for item in contract.arguments
            ),
            "normalized_instruction_count": len(instructions),
            "tainted_argument_count": len(taint.argument_evidence),
            "pointer_evidence_count": sum(
                len(items) for items in taint.pointer_evidence.values()
            ),
            "return_kind": legacy_contract.return_spec.kind,
            "compare_return": policy.compare_return,
            "executions": 0,
            "generated_tests": 0,
            "valid_original_executions": 0,
            "counterexamples": 0,
            "repair_iterations": 0,
            "elapsed_seconds": time.perf_counter() - started,
            "stop_reason": "static_contract_complete",
            "implemented_stages": [
                "privacy_gate",
                "elf_deep_facts",
                "static_contract_inference",
                "normalized_instruction_ir",
                "register_stack_address_taint",
                "void_safe_observation_policy",
                "initial_candidate_passthrough",
            ],
            "pending_stages": [
                "dynamic_contract_inference",
                "candidate_compilation",
                "differential_execution",
                "evidence_guided_repair",
            ],
        }
        _write_json(artifact_dir / "binoracle_metadata.json", metadata)
        return BinOracleResult(
            candidate_code=initial_code.strip(),
            summary="BinOracle completed ELF deep facts and conservative static audit.",
            metadata=metadata,
        )

    def _dynamic_run(
        self,
        *,
        facts,
        binary_path: Path,
        target_function: str,
        initial_code: str,
        optimization: str,
        sample_id: str,
        artifact_dir: Path,
        stage_dir: Path,
        started: float,
    ) -> BinOracleResult:
        assert self.contract_manifest is not None
        contract, input_cases = self.contract_manifest.resolve(
            sample_id=sample_id, function_name=target_function
        )
        if len(input_cases) > self.runner.max_executions:
            input_cases = input_cases[: self.runner.max_executions]
            stop_reason = "execution_budget_exhausted"
        else:
            stop_reason = "known_contract_inputs_complete"
        policy = ObservationPolicy(
            compare_return=contract.return_observable,
            compare_coverage=False,
            rationale=(
                "known contract controls whether RAX is observable",
                "this sprint queries only the original target.o",
            ),
        )
        contract_value = contract.to_dict()
        _write_json(stage_dir / "contract_candidates.json", [contract_value])
        _write_json(stage_dir / "selected_contract.json", contract_value)
        _write_json(stage_dir / "observation_policy.json", policy.to_dict())
        _write_json(
            stage_dir / "harness_manifest.json",
            {
                "schema_version": 1,
                "harness_version": self.runner.version,
                "abi": self.abi,
                "target": target_function,
                "contract_id": contract.contract_id,
                "isolation": "one forked child per InputCase",
                "guard_pages": True,
                "candidate_runner": False,
            },
        )
        build = self.runner.build_original(
            binary_path=binary_path,
            facts=facts,
            contract=contract,
            stage_dir=stage_dir,
        )
        input_values = [item.to_dict() for item in input_cases]
        _write_jsonl(stage_dir / "generated_inputs.jsonl", input_values)
        observations: list[dict[str, Any]] = []
        probe_history: list[dict[str, Any]] = []
        for index, input_case in enumerate(input_cases):
            observation, execution = self.runner.execute(
                build, contract=contract, input_case=input_case
            )
            observations.append(observation)
            probe_history.append(
                {
                    "probe": index,
                    "seed": input_case.seed,
                    "status": observation["status"],
                    "execution": execution,
                }
            )
        _write_jsonl(stage_dir / "original_observations.jsonl", observations)
        _write_jsonl(stage_dir / "probe_history.jsonl", probe_history)
        _write_jsonl(stage_dir / "candidate_observations.jsonl", [])
        _write_jsonl(stage_dir / "differences.jsonl", [])
        valid_original = sum(item["status"] == "returned" for item in observations)
        summary = {
            "schema_version": 1,
            "mode": self.mode,
            "contract_id": contract.contract_id,
            "generated_tests": len(input_cases),
            "executions": len(observations),
            "valid_original_executions": valid_original,
            "signals": sum(item["status"] == "signal" for item in observations),
            "timeouts": sum(item["status"] == "timeout" for item in observations),
            "candidate_executions": 0,
            "differences": 0,
            "stop_reason": stop_reason,
        }
        _write_json(stage_dir / "dynamic_summary.json", summary)
        metadata = {
            "schema_version": 1,
            "engine_version": self.version,
            "mode": self.mode,
            "sample_id": sample_id,
            "optimization": optimization,
            "executions": len(observations),
            "generated_tests": len(input_cases),
            "valid_original_executions": valid_original,
            "counterexamples": 0,
            "repair_iterations": 0,
            "contract_candidates": 1,
            "selected_contract": contract.contract_id,
            "return_kind": contract.return_kind,
            "compare_return": contract.return_observable,
            "harness_version": self.runner.version,
            "stop_reason": stop_reason,
            "elapsed_seconds": time.perf_counter() - started,
            "implemented_stages": [
                "privacy_gate",
                "elf_deep_facts",
                "known_contract_load",
                "abi_trampoline",
                "guard_page_object",
                "fork_isolated_original_execution",
                "inputcase_observation_protocol",
                "void_safe_observation",
                "initial_candidate_passthrough",
            ],
            "pending_stages": [
                "dynamic_contract_inference",
                "candidate_compilation",
                "differential_execution",
                "evidence_guided_repair",
            ],
        }
        _write_json(artifact_dir / "binoracle_metadata.json", metadata)
        return BinOracleResult(
            candidate_code=initial_code.strip(),
            summary=(
                f"BinOracle queried original target.o with {len(observations)} known-contract "
                "InputCase(s); candidate code was not modified."
            ),
            metadata=metadata,
        )

    def _execute_probe_batch(
        self,
        *,
        contract: ContractGraphV2,
        runner_contract,
        build: RunnerBuild,
        probes: tuple[Any, ...],
        binary_path: Path,
        facts,
        stage_dir: Path,
        candidate_dir: Path,
        phase: str,
        all_probe_records: list[dict[str, Any]],
        all_observations: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int, int]:
        """Execute a bounded batch of probes against the original target binary.

        Returns the observation list, total executions, and the number of
        ``returned`` observations. Appends each probe/observation pair to the
        shared audit records along with the supplied phase tag.
        """

        observations: list[dict[str, Any]] = []
        executed = 0
        valid = 0
        for probe in probes:
            observation, execution = self.runner.execute(
                build,
                contract=runner_contract,
                input_case=probe.input_case,
            )
            observations.append(observation)
            executed += 1
            valid += observation["status"] == "returned"
            all_probe_records.append(
                {"contract_id": contract.contract_id, "phase": phase, **probe.to_dict()}
            )
            all_observations.append(
                {
                    "contract_id": contract.contract_id,
                    "phase": phase,
                    "probe_id": probe.probe_id,
                    "observation": observation,
                    "execution": execution,
                }
            )
        return observations, executed, valid

    def _contract_probe_run(
        self,
        *,
        facts,
        binary_path: Path,
        target_function: str,
        initial_code: str,
        assembly: str,
        assembly_syntax: str,
        optimization: str,
        sample_id: str,
        artifact_dir: Path,
        stage_dir: Path,
        started: float,
    ) -> BinOracleResult:
        instructions = parse_assembly(assembly, syntax=assembly_syntax)
        taint = analyze_taint(instructions)
        candidates = generate_contract_candidates(
            taint,
            sample_id=sample_id,
            abi=self.abi,
            globals=facts.global_objects,
            dependencies=facts.dependencies,
            max_candidates=self.max_contract_candidates,
        )
        _write_jsonl(
            stage_dir / "normalized_ir.jsonl",
            [item.to_dict() for item in instructions],
        )
        _write_jsonl(stage_dir / "taint_trace.jsonl", list(taint.trace))
        _write_json(stage_dir / "taint_analysis.json", taint.to_dict())
        _write_json(
            stage_dir / "contract_candidates.json",
            [item.to_dict() for item in candidates],
        )

        resolution_budget = ResolutionBudget(
            max_rounds=self.resolution_max_rounds,
            max_executions=self.probe_executions_per_contract * self.max_contract_candidates,
            max_wall_seconds=float(self.config.get("resolution_max_wall_seconds", 120.0)),
        )
        resolution = HarnessResolutionState(sample_id=sample_id, budget=resolution_budget).transition(
            ResolutionStatus.STATIC_INFERRED,
            contract_ids=(item.contract_id for item in candidates),
            next_action="negotiate_capability",
        )
        capability_reports = {item.contract_id: assess_capability(item).to_dict() for item in candidates}
        _write_json(stage_dir / "capability_reports.json", capability_reports)
        resolution = resolution.transition(
            ResolutionStatus.CAPABILITY_CHECKED,
            contract_ids=(item.contract_id for item in candidates),
            next_action="execute_exploration_probes",
        )
        score_records: list[dict[str, Any]] = []
        probes_by_contract: dict[str, tuple[Any, ...]] = {}
        probe_counts: dict[str, int] = {}
        all_probe_records: list[dict[str, Any]] = []
        all_observations: list[dict[str, Any]] = []
        observations_by_contract: dict[str, list[dict[str, Any]]] = {}
        executed = 0
        valid_original = 0
        for candidate in candidates:
            candidate_dir = stage_dir / "contracts" / candidate.contract_id
            candidate_dir.mkdir(parents=True, exist_ok=True)
            capability = capability_reports[candidate.contract_id]
            if capability["status"] == "unsupported":
                score_records.append(
                    {
                        "contract_id": candidate.contract_id,
                        "status": "unsupported",
                        "reasons": capability["reasons"],
                        "capability": capability,
                    }
                )
                continue
            try:
                runner_contract = candidate.to_runner_contract()
                probes = generate_probe_plan(
                    candidate,
                    base_seed=self.probe_seed,
                    max_executions=min(
                        self.probe_executions_per_contract,
                        self.runner.max_executions,
                    ),
                    repetitions=self.probe_repetitions,
                )
            except ContractValidationError as error:
                score_records.append(
                    {
                        "contract_id": candidate.contract_id,
                        "status": "unsupported",
                        "reasons": list(candidate.unsupported_reasons) or [str(error)],
                    }
                )
                continue

            build = self.runner.build_original(
                binary_path=binary_path,
                facts=facts,
                contract=runner_contract,
                stage_dir=candidate_dir,
            )
            probes_by_contract[candidate.contract_id] = probes
            probe_counts[candidate.contract_id] = len(probes)
            probe_values = [item.to_dict() for item in probes]
            _write_jsonl(candidate_dir / "probe_plan.jsonl", probe_values)
            observations, round_executed, round_valid = self._execute_probe_batch(
                contract=candidate,
                runner_contract=runner_contract,
                build=build,
                probes=probes,
                binary_path=binary_path,
                facts=facts,
                stage_dir=stage_dir,
                candidate_dir=candidate_dir,
                phase="exploration",
                all_probe_records=all_probe_records,
                all_observations=all_observations,
            )
            executed += round_executed
            valid_original += round_valid
            observations_by_contract[candidate.contract_id] = list(observations)
            _write_jsonl(candidate_dir / "original_observations.jsonl", observations)
            score = score_contract(candidate, probes, tuple(observations))
            score_records.append({"status": "dynamic_scored", **score.to_dict()})

        runnable = [item for item in score_records if item["status"] == "dynamic_scored"]
        if not runnable:
            raise UnsupportedSample(
                "automatic_contract_no_runnable_candidate",
                "all automatic contract candidates exceed the current ABI runner boundary",
            )
        runnable.sort(key=lambda item: (-float(item["total"]), item["contract_id"]))
        resolution = resolution.transition(
            ResolutionStatus.PROBED,
            contract_ids=(item["contract_id"] for item in runnable),
            next_action="audit_exploration",
            budget=ResolutionBudget(
                max_rounds=resolution.budget.max_rounds,
                max_executions=resolution.budget.max_executions,
                max_wall_seconds=resolution.budget.max_wall_seconds,
                rounds_used=1,
                executions_used=executed,
                wall_seconds_used=time.perf_counter() - started,
            ),
        )
        leading_id = str(runnable[0]["contract_id"])
        selected_id: str | None = leading_id
        selection_status = "dynamic_scored_unreviewed"
        harness_frozen = False
        audit_value: dict[str, Any] | None = None
        active_probe_rounds: list[dict[str, Any]] = []
        ambiguity_resolution_record: dict[str, Any] | None = None
        if self.mode in {"contract_audit", "differential", "dynamic_repair"}:
            decision = audit_contracts(
                candidates,
                score_records,
                thresholds=self.audit_thresholds,
            )
            audit_value = decision.to_dict()
            _write_json(stage_dir / "audit_report.json", audit_value)
            if decision.decision == "accepted":
                selected_id = decision.selected_contract
                selection_status = "audit_accepted_pending_holdout"
            elif decision.decision == "ambiguous":
                # WP5: ambiguity discrimination. Generate deterministic
                # discriminative probes that are safe under every competing
                # candidate, execute them on the original binary, and re-audit.
                # If every competitor still agrees on a winner above the score
                # margin, accept it; otherwise emit a behavioural equivalence
                # class and treat the sample as unidentifiable from binary.
                competing = [
                    item for item in candidates
                    if item.contract_id in set(decision.competing_contracts)
                ]
                ambiguity_resolution_record, executed, valid_original, resolution, selected_id, selection_status, audit_value = (
                    self._resolve_ambiguity(
                        competing=competing,
                        binary_path=binary_path,
                        facts=facts,
                        stage_dir=stage_dir,
                        started=started,
                        executed=executed,
                        valid_original=valid_original,
                        resolution=resolution,
                        all_probe_records=all_probe_records,
                        all_observations=all_observations,
                        audit_value=audit_value,
                        selection_status=f"audit_{decision.decision}",
                    )
                )
            else:  # rejected
                selected_id, selection_status, resolution, executed, valid_original, audit_value = (
                    self._active_probe_loop(
                        candidates=candidates,
                        score_records=score_records,
                        probes_by_contract=probes_by_contract,
                        observations_by_contract=observations_by_contract,
                        probe_counts=probe_counts,
                        binary_path=binary_path,
                        facts=facts,
                        stage_dir=stage_dir,
                        started=started,
                        executed=executed,
                        valid_original=valid_original,
                        resolution=resolution,
                        decision=decision,
                        all_probe_records=all_probe_records,
                        all_observations=all_observations,
                        audit_value=audit_value,
                        selection_status=f"audit_{decision.decision}",
                    )
                )
                active_probe_rounds = audit_value.get("active_probe_rounds", []) if audit_value else []
        _write_json(stage_dir / "contract_scores.json", score_records)
        _write_json(
            stage_dir / "leading_contract.json",
            next(item for item in candidates if item.contract_id == leading_id).to_dict(),
        )
        if ambiguity_resolution_record is not None:
            _write_json(
                stage_dir / "ambiguity_resolution.json",
                ambiguity_resolution_record,
            )
        if active_probe_rounds:
            _write_jsonl(
                stage_dir / "active_probe_rounds.jsonl",
                active_probe_rounds,
            )
        holdout_plan = None
        if selected_id is not None:
            selected = next(
                item for item in candidates if item.contract_id == selected_id
            )
            _write_json(stage_dir / "selected_contract.json", selected.to_dict())
            if self.mode in {"contract_audit", "differential", "dynamic_repair"} and audit_value and audit_value["decision"] == "accepted":
                holdout_plan = commit_holdout(
                    selected,
                    probe_seed=self.probe_seed,
                    max_executions=min(self.holdout_executions, self.runner.max_executions),
                    repetitions=self.probe_repetitions,
                )
                selected_dir = stage_dir / "contracts" / selected.contract_id
                selected_runner = selected.to_runner_contract()
                selected_build = RunnerBuild(selected_dir / "original_runner.x", {})
                holdout_observations: list[dict[str, Any]] = []
                holdout_executed = 0
                for probe in holdout_plan.probes:
                    observation, execution = self.runner.execute(
                        selected_build, contract=selected_runner, input_case=probe.input_case
                    )
                    holdout_observations.append(observation)
                    holdout_executed += 1
                    executed += 1
                    valid_original += observation["status"] == "returned"
                    all_probe_records.append({"contract_id": selected.contract_id, "phase": "holdout", **probe.to_dict()})
                    all_observations.append({"contract_id": selected.contract_id, "phase": "holdout", "probe_id": probe.probe_id, "observation": observation, "execution": execution})
                _write_jsonl(selected_dir / "holdout_probe_plan.jsonl", [item.to_dict() for item in holdout_plan.probes])
                _write_jsonl(selected_dir / "holdout_observations.jsonl", holdout_observations)
                holdout_score = score_contract(selected, holdout_plan.probes, tuple(holdout_observations))
                holdout_decision = audit_contracts([selected], [{"status": "dynamic_scored", **holdout_score.to_dict()}], thresholds=self.audit_thresholds)
                _write_json(selected_dir / "holdout_audit.json", holdout_decision.to_dict())
                if holdout_decision.decision == "accepted":
                    harness_frozen = True
                    selection_status = "audit_accepted_holdout_frozen"
                    resolution = resolution.transition(ResolutionStatus.FROZEN, contract_ids=(selected.contract_id,), next_action=None)
                else:
                    selected_id = None
                    selection_status = "holdout_" + holdout_decision.decision
                    resolution = resolution.transition(ResolutionStatus.RETRYABLE_REJECTED, reasons=holdout_decision.reasons, contract_ids=(selected.contract_id,), next_action="failure_directed_probe")
                audit_value["holdout"] = holdout_decision.to_dict()
            if harness_frozen and selected_id is not None and holdout_plan is not None:
                observation_policy = ObservationPolicy(
                    compare_return=selected.return_spec.observable,
                    compare_coverage=False,
                    rationale=(
                        "return comparison follows the accepted contract hypothesis",
                        "coverage is unavailable and is not approximated",
                    ),
                ).to_dict()
                _write_json(stage_dir / "observation_policy.json", observation_policy)
                manifest = freeze_harness_manifest(
                    contract=selected,
                    probes=probes_by_contract[selected.contract_id],
                    holdout_probes=holdout_plan.probes,
                    holdout=holdout_plan.commitment,
                    capability_report=capability_reports[selected.contract_id],
                    observation_policy=observation_policy,
                    runner_version=self.runner.version,
                    target_function=target_function,
                    probe_seed=self.probe_seed,
                    resource_limits={
                        "execution_timeout_ms": self.runner.execution_timeout_ms,
                        "max_executions": self.runner.max_executions,
                    },
                )
                _write_json(stage_dir / "harness_manifest.json", manifest)
        _write_jsonl(stage_dir / "probe_plan.jsonl", all_probe_records)
        _write_jsonl(stage_dir / "original_observations.jsonl", all_observations)
        _write_json(stage_dir / "harness_resolution.json", resolution.to_dict())
        _write_json(
            stage_dir / "dynamic_probe_summary.json",
            {
                "schema_version": 1,
                "selection_status": selection_status,
                "selected_contract": selected_id,
                "leading_contract": leading_id,
                "contract_candidates": len(candidates),
                "runnable_contracts": len(runnable),
                "executions": executed,
                "valid_original_executions": valid_original,
                "harness_frozen": harness_frozen,
                "resolution": resolution.to_dict(),
                "audit": audit_value,
                "capability_reports": capability_reports,
            },
        )
        metadata = {
            "schema_version": 1,
            "engine_version": self.version,
            "mode": self.mode,
            "sample_id": sample_id,
            "optimization": optimization,
            "contract_candidates": len(candidates),
            "runnable_contracts": len(runnable),
            "selected_contract": selected_id,
            "leading_contract": leading_id,
            "contract_selection_status": selection_status,
            "harness_frozen": harness_frozen,
            "resolution_state": resolution.to_dict(),
            "executions": executed,
            "generated_tests": len(all_probe_records),
            "valid_original_executions": valid_original,
            "counterexamples": 0,
            "repair_iterations": 0,
            "elapsed_seconds": time.perf_counter() - started,
            "stop_reason": (
                "harness_frozen"
                if harness_frozen
                else "dynamic_contract_scoring_complete_audit_pending"
                if self.mode == "contract_probe"
                else selection_status
            ),
            "implemented_stages": [
                "privacy_gate",
                "elf_deep_facts",
                "normalized_instruction_ir",
                "register_stack_address_taint",
                "top_k_contract_generation",
                "deterministic_probe_plan",
                "guard_page_original_execution",
                "dynamic_contract_scoring",
                *(
                    ["contract_auditor"]
                    if self.mode in {"contract_audit", "differential", "dynamic_repair"}
                    else []
                ),
                *(["harness_freeze"] if harness_frozen else []),
            ],
            "pending_stages": [
                *(
                    ["contract_auditor", "harness_freeze"]
                    if self.mode == "contract_probe"
                    else [] if harness_frozen else ["harness_freeze"]
                ),
                "candidate_compilation",
                "differential_execution",
                "evidence_guided_repair",
            ],
        }
        _write_json(artifact_dir / "binoracle_metadata.json", metadata)
        return BinOracleResult(
            candidate_code=initial_code.strip(),
            summary=(
                f"BinOracle dynamically scored {len(runnable)} automatic contract "
                f"candidate(s); selection status is {selection_status}."
            ),
            metadata=metadata,
        )

    def _active_probe_loop(
        self,
        *,
        candidates: list[ContractGraphV2],
        score_records: list[dict[str, Any]],
        probes_by_contract: dict[str, tuple[Any, ...]],
        observations_by_contract: dict[str, list[dict[str, Any]]],
        probe_counts: dict[str, int],
        binary_path: Path,
        facts,
        stage_dir: Path,
        started: float,
        executed: int,
        valid_original: int,
        resolution: HarnessResolutionState,
        decision,
        all_probe_records: list[dict[str, Any]],
        all_observations: list[dict[str, Any]],
        audit_value: dict[str, Any],
        selection_status: str,
    ) -> tuple[str | None, str, HarnessResolutionState, int, int, dict[str, Any]]:
        """WP4: failure-directed active probing.

        After the exploration audit rejects the leading candidate, run a bounded
        number of additional probe rounds. Each round derives its probes from the
        failure reason codes (effect/boundary/stability), executes them only on
        the original binary, re-scores, and re-audits. The loop stops when the
        auditor accepts the leading candidate, when no new information has been
        gathered for two consecutive rounds, or when the resolution budget is
        exhausted. Auditor thresholds are never weakened here; the active prober
        only adds bounded, auditable evidence.
        """

        selected_id: str | None = None
        active_rounds: list[dict[str, Any]] = []
        no_information_rounds = 0
        risk_upper_bound = 0.0
        risk_limit = 1.0 - self.audit_thresholds.min_valid
        max_round_budget = self.resolution_max_rounds
        round_index = 0
        latest_decision = decision
        while True:
            round_index += 1
            budget = ResolutionBudget(
                max_rounds=resolution.budget.max_rounds,
                max_executions=resolution.budget.max_executions,
                max_wall_seconds=resolution.budget.max_wall_seconds,
                rounds_used=resolution.budget.rounds_used + round_index,
                executions_used=executed,
                wall_seconds_used=time.perf_counter() - started,
            )
            stop_reason = should_stop_active_probing(
                no_information_rounds=no_information_rounds,
                risk_upper_bound=risk_upper_bound,
                risk_limit=risk_limit,
                budget_exhausted=budget.exhausted or round_index > max_round_budget,
            )
            if stop_reason is not None:
                break

            # Only re-probe the previously-rejected leader; competing contracts
            # are handled by the ambiguity branch, not by this loop.
            leader_id = latest_decision.competing_contracts[0] if latest_decision.competing_contracts else None
            if leader_id is None:
                leader_id = max(
                    score_records,
                    key=lambda item: float(item.get("total", 0.0)),
                ).get("contract_id")
            if not leader_id:
                break
            leader = next(item for item in candidates if item.contract_id == leader_id)
            leader_dir = stage_dir / "contracts" / leader.contract_id
            leader_dir.mkdir(parents=True, exist_ok=True)
            try:
                leader_runner_contract = leader.to_runner_contract()
            except ContractValidationError as error:
                selection_status = "active_probe_unsupported"
                resolution = resolution.transition(
                    ResolutionStatus.UNVERIFIED,
                    reasons=(str(error),),
                    next_action=None,
                )
                audit_value["decision"] = "rejected"
                audit_value["active_probe_rounds"] = active_rounds
                return None, selection_status, resolution, executed, valid_original, audit_value

            remaining = max(
                1,
                min(
                    self.probe_executions_per_contract,
                    self.runner.max_executions,
                    resolution.budget.max_executions - executed,
                ),
            )
            generation = generate_failure_directed_probes(
                leader,
                latest_decision.reasons,
                base_seed=self.probe_seed,
                round_index=round_index,
                max_executions=remaining,
                repetitions=self.probe_repetitions,
            )
            round_probes = generation.probes
            if not round_probes:
                break
            round_path = leader_dir / f"active_probe_round-{round_index:02d}.jsonl"
            _write_jsonl(round_path, [item.to_dict() for item in round_probes])
            build = self.runner.build_original(
                binary_path=binary_path,
                facts=facts,
                contract=leader_runner_contract,
                stage_dir=leader_dir,
            )
            observations, round_executed, round_valid = self._execute_probe_batch(
                contract=leader,
                runner_contract=leader_runner_contract,
                build=build,
                probes=round_probes,
                binary_path=binary_path,
                facts=facts,
                stage_dir=stage_dir,
                candidate_dir=leader_dir,
                phase=f"active_probe_round_{round_index:02d}",
                all_probe_records=all_probe_records,
                all_observations=all_observations,
            )
            executed += round_executed
            valid_original += round_valid

            prior_score_total = float(
                next(
                    (
                        record.get("total", 0.0)
                        for record in score_records
                        if record.get("contract_id") == leader.contract_id
                    ),
                    0.0,
                )
            )

            combined_probes = tuple(probes_by_contract[leader.contract_id]) + round_probes
            combined_observations = list(observations_by_contract[leader.contract_id]) + observations
            score = score_contract(leader, combined_probes, tuple(combined_observations))
            for record in score_records:
                if record.get("contract_id") == leader.contract_id:
                    record.clear()
                    record.update({"status": "dynamic_scored", **score.to_dict()})
                    break
            probes_by_contract[leader.contract_id] = combined_probes
            probe_counts[leader.contract_id] = len(combined_probes)
            observations_by_contract[leader.contract_id] = combined_observations
            _write_jsonl(
                leader_dir / "probe_plan.jsonl",
                [item.to_dict() for item in combined_probes],
            )
            _write_jsonl(
                leader_dir / "original_observations.jsonl",
                combined_observations,
            )

            information_gain = max(0.0, float(score.total) - prior_score_total)
            if information_gain <= 0.0:
                no_information_rounds += 1
            else:
                no_information_rounds = 0
            risk_upper_bound = max(risk_upper_bound, max(0.0, 1.0 - float(score.valid)))

            latest_decision = audit_contracts(
                [leader],
                [
                    record
                    for record in score_records
                    if record.get("contract_id") == leader.contract_id
                ],
                thresholds=self.audit_thresholds,
            )
            active_rounds.append(
                {
                    "schema_version": "binoracle.active-probe-round.v1",
                    "round_index": round_index,
                    "strategy": generation.strategy,
                    "reason_codes": list(generation.reason_codes),
                    "probe_count": len(round_probes),
                    "executions": round_executed,
                    "valid_executions": round_valid,
                    "information_gain": information_gain,
                    "audit_decision": latest_decision.decision,
                    "no_information_rounds": no_information_rounds,
                    "stop_reason": None,
                }
            )
            if latest_decision.decision == "accepted":
                selected_id = latest_decision.selected_contract
                audit_value["decision"] = "accepted"
                audit_value["reasons"] = list(latest_decision.reasons)
                audit_value["threshold_gaps"] = latest_decision.threshold_gaps
                audit_value["active_probe_rounds"] = active_rounds
                resolution = resolution.transition(
                    ResolutionStatus.PROBED,
                    contract_ids=(leader.contract_id,),
                    next_action="audit_exploration",
                )
                return (
                    selected_id,
                    "audit_accepted_pending_holdout",
                    resolution,
                    executed,
                    valid_original,
                    audit_value,
                )

        # Budget/no-information stop. The active prober was unable to gather
        # enough evidence to accept any candidate. The exploration phase must
        # not freeze; hand the sample off to a terminal state with the rejection
        # recorded, never the audit-accepted state.
        terminal_reason = stop_reason or "budget_exhausted"
        resolution = resolution.transition(
            ResolutionStatus.BUDGET_EXHAUSTED
            if terminal_reason == "budget_exhausted"
            else ResolutionStatus.UNVERIFIED,
            reasons=(terminal_reason,),
            next_action=None,
        )
        audit_value["decision"] = "rejected"
        audit_value["active_probe_rounds"] = active_rounds
        if active_rounds:
            active_rounds[-1]["stop_reason"] = terminal_reason
        return None, f"active_probe_{terminal_reason}", resolution, executed, valid_original, audit_value

    def _resolve_ambiguity(
        self,
        *,
        competing: list[ContractGraphV2],
        binary_path: Path,
        facts,
        stage_dir: Path,
        started: float,
        executed: int,
        valid_original: int,
        resolution: HarnessResolutionState,
        all_probe_records: list[dict[str, Any]],
        all_observations: list[dict[str, Any]],
        audit_value: dict[str, Any],
        selection_status: str,
    ) -> tuple[dict[str, Any] | None, int, int, HarnessResolutionState, str | None, str, dict[str, Any]]:
        """WP5: ambiguity discrimination.

        Run a deterministic set of discriminative probes (each safe under every
        competing candidate) against the original binary, score each candidate
        interpretation, and decide:

          - If a unique winner emerges above the score margin, accept it.
          - Otherwise emit a behavioural equivalence class and mark the sample
            as unidentifiable from binary (no static prior is allowed to force a
            top-1 selection).
        """

        if not competing:
            resolution = resolution.transition(
                ResolutionStatus.UNIDENTIFIABLE_FROM_BINARY,
                reasons=("no_competing_contracts",),
                next_action=None,
            )
            audit_value["decision"] = "ambiguous"
            record = {
                "schema_version": "binoracle.ambiguity-resolution.v1",
                "status": "unidentifiable_from_binary",
                "competing_contracts": [],
                "reason": "no competing contracts were supplied to the discriminator",
                "safe_probe_count": 0,
            }
            return record, executed, valid_original, resolution, None, selection_status, audit_value

        budget_cap = max(
            1,
            min(
                self.probe_executions_per_contract,
                self.runner.max_executions,
                resolution.budget.max_executions - executed,
            ),
        )
        discriminative = generate_discriminative_probes(
            competing,
            base_seed=self.probe_seed,
            max_executions=budget_cap,
            repetitions=self.probe_repetitions,
        )
        ambiguous_dir = stage_dir / "ambiguity"
        ambiguous_dir.mkdir(parents=True, exist_ok=True)
        _write_jsonl(
            ambiguous_dir / "discriminative_probes.jsonl",
            [probe.to_dict() for probe in discriminative],
        )

        candidate_scores: list[dict[str, Any]] = []
        # Score each competing candidate interpretation against the same
        # deterministic observations. We execute each probe exactly once per
        # candidate under its own runner contract so the comparisons reflect
        # genuine behavioural disagreement, never just probe shape differences.
        per_candidate_observations: dict[str, list[dict[str, Any]]] = {}
        for candidate in competing:
            candidate_dir = stage_dir / "contracts" / candidate.contract_id
            candidate_dir.mkdir(parents=True, exist_ok=True)
            try:
                runner_contract = candidate.to_runner_contract()
            except ContractValidationError as error:
                candidate_scores.append(
                    {
                        "contract_id": candidate.contract_id,
                        "status": "unsupported",
                        "reason": str(error),
                    }
                )
                continue
            build = self.runner.build_original(
                binary_path=binary_path,
                facts=facts,
                contract=runner_contract,
                stage_dir=candidate_dir,
            )
            observations, round_executed, round_valid = self._execute_probe_batch(
                contract=candidate,
                runner_contract=runner_contract,
                build=build,
                probes=discriminative,
                binary_path=binary_path,
                facts=facts,
                stage_dir=stage_dir,
                candidate_dir=candidate_dir,
                phase="discriminative",
                all_probe_records=all_probe_records,
                all_observations=all_observations,
            )
            executed += round_executed
            valid_original += round_valid
            per_candidate_observations[candidate.contract_id] = observations
            score = score_contract(candidate, discriminative, tuple(observations))
            candidate_scores.append(
                {"status": "dynamic_scored", **score.to_dict()}
            )

        # Compare candidates pairwise on the executed observations: if their
        # observable behaviour is byte-for-byte identical we cannot identify a
        # unique winner from binary alone.
        candidate_ids = [item.contract_id for item in competing]
        observation_signatures = {
            cid: tuple(
                json.dumps(obs, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for obs in per_candidate_observations.get(cid, [])
            )
            for cid in candidate_ids
        }
        all_identical = len({observation_signatures[cid] for cid in candidate_ids}) == 1
        scored_records = [
            item for item in candidate_scores if item.get("status") == "dynamic_scored"
        ]
        if scored_records and not all_identical:
            scored_records.sort(
                key=lambda item: (-float(item.get("total", 0.0)), str(item.get("contract_id")))
            )
            best = scored_records[0]
            competitors = [
                item for item in scored_records[1:]
                if float(best.get("total", 0.0)) - float(item.get("total", 0.0))
                < self.audit_thresholds.min_score_margin
            ]
            if not competitors:
                winner_id = str(best["contract_id"])
                resolution = resolution.transition(
                    ResolutionStatus.PROBED,
                    contract_ids=(winner_id,),
                    next_action="audit_exploration",
                )
                audit_value["decision"] = "accepted"
                audit_value["selected_contract"] = winner_id
                audit_value["reasons"] = ["ambiguity_distinguished"]
                record = {
                    "schema_version": "binoracle.ambiguity-resolution.v1",
                    "status": "discriminated",
                    "competing_contracts": candidate_ids,
                    "behavioral_contract": winner_id,
                    "safe_probe_count": len(discriminative),
                    "candidate_scores": candidate_scores,
                    "reason": "deterministic discriminative probes selected a unique winner",
                }
                return (
                    record,
                    executed,
                    valid_original,
                    resolution,
                    winner_id,
                    "audit_accepted_pending_holdout",
                    audit_value,
                )

        equivalence = equivalent_if_no_disagreement(
            competing,
            safe_probe_count=len(discriminative),
        )
        resolution = resolution.transition(
            ResolutionStatus.BEHAVIORAL_EQUIVALENCE_CLASS,
            reasons=("ambiguity_not_distinguishable_from_binary",),
            contract_ids=tuple(item.contract_id for item in competing),
            next_action=None,
        )
        audit_value["decision"] = "ambiguous"
        audit_value["reasons"] = list(audit_value.get("reasons", [])) + [
            "behavioral_equivalence_class_emitted"
        ]
        record = equivalence.to_dict()
        record["competing_contracts"] = candidate_ids
        record["candidate_scores"] = candidate_scores
        record["safe_probe_count"] = len(discriminative)
        record["all_observations_identical"] = all_identical
        return (
            record,
            executed,
            valid_original,
            resolution,
            None,
            "ambiguity_unidentifiable_from_binary",
            audit_value,
        )

    def _differential_run(
        self,
        *,
        base_result: BinOracleResult,
        facts,
        target_function: str,
        initial_code: str,
        optimization: str,
        artifact_dir: Path,
        stage_dir: Path,
        candidate_code: str | None = None,
        candidate_dir: Path | None = None,
    ) -> BinOracleResult:
        candidate_code = candidate_code if candidate_code is not None else initial_code
        for stale_name in (
            "differential_summary.json",
            "candidate_observations.jsonl",
            "differences.jsonl",
            "evidence_packages.jsonl",
        ):
            stale_path = stage_dir / stale_name
            if stale_path.is_file():
                stale_path.unlink()
        metadata_path = artifact_dir / "binoracle_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if not metadata.get("harness_frozen"):
            metadata.update(
                {
                    "candidate_compile": False,
                    "candidate_link": False,
                    "differential_pass": False,
                    "differential_stop_reason": "harness_not_frozen",
                }
            )
            _write_json(metadata_path, metadata)
            return BinOracleResult(
                candidate_code=candidate_code,
                summary=base_result.summary + " Candidate differential was skipped.",
                metadata=metadata,
            )

        selected_value = json.loads(
            (stage_dir / "selected_contract.json").read_text(encoding="utf-8")
        )
        selected = ContractGraphV2.from_dict(selected_value)
        runner_contract = selected.to_runner_contract()
        # Phase 3 / WP8: never regenerate the exploration probes here. The
        # frozen harness committed to a specific probe plan and observation set,
        # so the differential comparison must replay those exact probes against
        # the candidate. Reading them from disk lets the frozen manifest's
        # content hash pin the comparison.
        contract_dir = stage_dir / "contracts" / selected.contract_id
        probe_records = _read_jsonl(contract_dir / "probe_plan.jsonl")
        harness_manifest = json.loads(
            (stage_dir / "harness_manifest.json").read_text(encoding="utf-8")
        )
        if not probe_records:
            raise RunnerError(
                "frozen harness is missing the exploration probe_plan.jsonl artifact"
            )
        frozen_probe_hash = hashlib.sha256(
            json.dumps(
                probe_records,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if frozen_probe_hash != str(
            harness_manifest.get("probe_plan_hash", "")
        ):
            raise RunnerError(
                "frozen exploration probe_plan.jsonl hash does not match the harness manifest"
            )
        probes = tuple(
            _probe_from_record(record, selected, runner_contract)
            for record in probe_records
        )
        original_observations = _read_jsonl(
            contract_dir / "original_observations.jsonl"
        )
        if len(original_observations) != len(probes):
            raise RunnerError(
                "frozen original observations do not match the frozen probe plan"
            )

        candidate_dir = candidate_dir or (stage_dir / "candidate")
        compilation = self.candidate_compiler.compile(
            code=candidate_code,
            function_name=target_function,
            optimization=optimization,
            stage_dir=candidate_dir,
        )
        _write_json(candidate_dir / "candidate_compile.json", compilation.manifest)
        if not compilation.success:
            summary = {
                "schema_version": 1,
                "candidate_compile": False,
                "candidate_compile_gate": False if self.candidate_compiler.compile_gate_enabled else None,
                "candidate_link": False,
                "differential_pass": False,
                "reason": (
                    "candidate_compile_timeout"
                    if compilation.manifest["timed_out"]
                    else "candidate_compile_error"
                ),
            }
            _write_json(stage_dir / "differential_summary.json", summary)
            metadata.update(summary)
            metadata["stop_reason"] = summary["reason"]
            _write_json(metadata_path, metadata)
            return BinOracleResult(
                candidate_code=candidate_code,
                summary="BinOracle froze the Harness, but candidate compilation failed.",
                metadata=metadata,
            )

        compile_gate = self.candidate_compiler.compile_gate(
            code=candidate_code,
            function_name=target_function,
            optimization=optimization,
            stage_dir=candidate_dir,
        )
        if compile_gate is not None:
            _write_json(candidate_dir / "candidate_compile_gate.json", compile_gate.manifest)
            if not compile_gate.success:
                summary = {
                    "schema_version": 1,
                    "candidate_compile": True,
                    "candidate_compile_gate": False,
                    "candidate_link": False,
                    "differential_pass": False,
                    "reason": (
                        "candidate_compile_gate_timeout"
                        if compile_gate.manifest["timed_out"]
                        else "candidate_compile_gate_error"
                    ),
                }
                _write_json(stage_dir / "differential_summary.json", summary)
                metadata.update(summary)
                metadata["stop_reason"] = summary["reason"]
                _write_json(metadata_path, metadata)
                return BinOracleResult(
                    candidate_code=candidate_code,
                    summary=(
                        "BinOracle rejected the candidate at the public wrapper-compatible "
                        "compile gate."
                    ),
                    metadata=metadata,
                )

        try:
            candidate_runner = self.runner.build_candidate(
                candidate_object=compilation.object,
                facts=facts,
                contract=runner_contract,
                stage_dir=candidate_dir,
            )
        except RunnerError as error:
            summary = {
                "schema_version": 1,
                "candidate_compile": True,
                "candidate_compile_gate": (
                    True if self.candidate_compiler.compile_gate_enabled else None
                ),
                "candidate_link": False,
                "differential_pass": False,
                "reason": "candidate_link_error",
                "error": str(error),
            }
            _write_json(stage_dir / "differential_summary.json", summary)
            metadata.update(summary)
            metadata["stop_reason"] = summary["reason"]
            _write_json(metadata_path, metadata)
            return BinOracleResult(
                candidate_code=candidate_code,
                summary="BinOracle froze the Harness, but candidate runner linkage failed.",
                metadata=metadata,
            )

        policy = json.loads(
            (stage_dir / "observation_policy.json").read_text(encoding="utf-8")
        )
        candidate_observations: list[dict[str, Any]] = []
        candidate_raw_observations: list[dict[str, Any]] = []
        differences: list[dict[str, Any]] = []
        for probe, original in zip(probes, original_observations):
            candidate, execution = self.runner.execute(
                candidate_runner,
                contract=runner_contract,
                input_case=probe.input_case,
            )
            candidate_observations.append(
                {
                    "probe_id": probe.probe_id,
                    "observation": candidate,
                    "execution": execution,
                }
            )
            candidate_raw_observations.append(candidate)
            difference = compare_observations(
                probe.probe_id,
                original,
                candidate,
                compare_return=bool(policy.get("compare_return")),
                compare_globals=bool(policy.get("compare_globals", True)),
            )
            differences.append(difference.to_dict())
        _write_jsonl(stage_dir / "candidate_observations.jsonl", candidate_observations)
        _write_jsonl(stage_dir / "differences.jsonl", differences)
        mismatch_count = sum(not item["equivalent"] for item in differences)
        # harness_manifest was loaded earlier, right after the contract was
        # reconstructed from the frozen selected_contract.json artifact.
        original_runner = RunnerBuild(
            stage_dir
            / "contracts"
            / selected.contract_id
            / "original_runner.x",
            {},
        )
        minimization_executions = 0
        evidence_packages: list[dict[str, Any]] = []
        minimized_count = 0
        seen_evidence_groups: set[tuple[str, tuple[str, ...]]] = set()
        for probe, original, candidate, difference in zip(
            probes,
            original_observations,
            candidate_raw_observations,
            differences,
        ):
            if difference["equivalent"]:
                continue
            evidence_group = (probe.stability_group, tuple(difference["kinds"]))
            if evidence_group in seen_evidence_groups:
                continue
            seen_evidence_groups.add(evidence_group)
            minimized = None
            if (
                self.minimize_counterexamples
                and minimized_count < self.max_minimized_counterexamples
                and self.max_minimization_attempts > 0
            ):
                def remains_counterexample(input_case):
                    nonlocal minimization_executions
                    original_retry, _ = self.runner.execute(
                        original_runner,
                        contract=runner_contract,
                        input_case=input_case,
                    )
                    candidate_retry, _ = self.runner.execute(
                        candidate_runner,
                        contract=runner_contract,
                        input_case=input_case,
                    )
                    minimization_executions += 2
                    retry_difference = compare_observations(
                        f"diagnostic:{probe.probe_id}",
                        original_retry,
                        candidate_retry,
                        compare_return=bool(policy.get("compare_return")),
                        compare_globals=bool(policy.get("compare_globals", True)),
                    )
                    return not retry_difference.equivalent

                minimized = minimize_counterexample(
                    probe,
                    contract=runner_contract,
                    is_counterexample=remains_counterexample,
                    max_attempts=self.max_minimization_attempts,
                )
                minimized_count += 1
            evidence_packages.append(
                build_evidence_package(
                    sample_id=selected.sample_id,
                    contract_hash=selected.content_hash,
                    harness_hash=str(harness_manifest["content_hash"]),
                    probe=probe,
                    original=original,
                    candidate=candidate,
                    difference=difference,
                    minimized=minimized,
                )
            )
        _write_jsonl(stage_dir / "evidence_packages.jsonl", evidence_packages)
        kind_counts: dict[str, int] = {}
        for item in differences:
            for kind in item["kinds"]:
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
        summary = {
            "schema_version": 1,
            "candidate_compile": True,
            "candidate_compile_gate": (
                True if self.candidate_compiler.compile_gate_enabled else None
            ),
            "candidate_link": True,
            "differential_pass": mismatch_count == 0,
            "tests_total": len(differences),
            "tests_passed": len(differences) - mismatch_count,
            "differences": mismatch_count,
            "difference_kinds": dict(sorted(kind_counts.items())),
            "evidence_packages": len(evidence_packages),
            "minimized_counterexamples": minimized_count,
            "minimization_executions": minimization_executions,
            "reason": None if mismatch_count == 0 else "behavior_mismatch",
        }
        _write_json(stage_dir / "differential_summary.json", summary)
        metadata.update(summary)
        metadata["executions"] = (
            int(metadata.get("executions", 0))
            + len(probes)
            + minimization_executions
        )
        metadata["counterexamples"] = mismatch_count
        metadata["stop_reason"] = (
            "differential_equivalent" if mismatch_count == 0 else "counterexamples_found"
        )
        metadata["implemented_stages"] = [
            *metadata.get("implemented_stages", []),
            "candidate_compile",
            "candidate_runner",
            "frozen_harness_differential_execution",
            "observation_difference_classification",
            "counterexample_evidence_package",
            *( ["counterexample_input_minimization"] if minimized_count else [] ),
        ]
        _write_json(metadata_path, metadata)
        return BinOracleResult(
            candidate_code=candidate_code,
            summary=(
                f"BinOracle compared {len(differences)} frozen probes and found "
                f"{mismatch_count} behavioral difference(s)."
            ),
            metadata=metadata,
        )

    def _dynamic_repair_run(
        self,
        *,
        base_result: BinOracleResult,
        facts,
        target_function: str,
        initial_code: str,
        optimization: str,
        sample_id: str,
        artifact_dir: Path,
        stage_dir: Path,
    ) -> BinOracleResult:
        metadata_path = artifact_dir / "binoracle_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        state = RepairState.INITIAL
        state_trace = [state.value]

        def move(target: RepairState) -> None:
            nonlocal state
            validate_transition(state, target)
            state = target
            state_trace.append(state.value)

        repair_dir = stage_dir / "repair"
        repair_dir.mkdir(parents=True, exist_ok=True)
        if not metadata.get("harness_frozen"):
            move(RepairState.UNSUPPORTED)
            summary = {
                "schema_version": "binoracle.dynamic-repair-summary.v1",
                "status": state.value,
                "repairer_version": self.repairer.version,
                "repair_iterations": 0,
                "state_trace": state_trace,
                "reason": "harness_not_frozen",
            }
            _write_json(stage_dir / "repair_summary.json", summary)
            metadata.update(
                {
                    "repair_status": state.value,
                    "repair_iterations": 0,
                    "repair_state_trace": state_trace,
                    "stop_reason": "harness_not_frozen",
                }
            )
            _write_json(metadata_path, metadata)
            return BinOracleResult(
                candidate_code=initial_code,
                summary="BinOracle dynamic repair requires an accepted frozen Harness.",
                metadata=metadata,
            )

        harness_path = stage_dir / "harness_manifest.json"
        harness = json.loads(harness_path.read_text(encoding="utf-8"))
        frozen_file_hash = hashlib.sha256(harness_path.read_bytes()).hexdigest()
        frozen_content_hash = str(harness["content_hash"])
        candidate_source = initial_code
        repair_requests: list[dict[str, Any]] = []
        repair_responses: list[dict[str, Any]] = []
        iterations: list[dict[str, Any]] = []
        repair_count = 0
        model_call_count = 0
        model_tokens_used = 0
        model_call_audits: list[dict[str, Any]] = []
        seen_source_hashes = {
            hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()
        }
        final_reason = "unknown"
        checkpoint_path = repair_dir / "checkpoint.json"

        def checkpoint_hash(value: dict[str, Any]) -> str:
            return hashlib.sha256(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()

        def save_checkpoint() -> None:
            core = {
                "schema_version": "binoracle.dynamic-repair-checkpoint.v1",
                "sample_id": sample_id,
                "frozen_harness_hash": frozen_content_hash,
                "state": state.value,
                "state_trace": state_trace,
                "candidate_source": candidate_source,
                "repair_count": repair_count,
                "model_call_count": model_call_count,
                "model_tokens_used": model_tokens_used,
                "model_call_audits": model_call_audits,
                "seen_source_hashes": sorted(seen_source_hashes),
                "repair_requests": repair_requests,
                "repair_responses": repair_responses,
                "iterations": iterations,
                "final_reason": final_reason,
            }
            _write_json(checkpoint_path, {**core, "content_hash": checkpoint_hash(core)})

        if self.repair_resume and checkpoint_path.is_file():
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            expected_checkpoint_hash = checkpoint.pop("content_hash", None)
            if expected_checkpoint_hash != checkpoint_hash(checkpoint):
                raise RunnerError("dynamic repair checkpoint content hash is invalid")
            if checkpoint.get("sample_id") != sample_id:
                raise RunnerError("dynamic repair checkpoint sample_id does not match")
            if checkpoint.get("frozen_harness_hash") != frozen_content_hash:
                raise RunnerError("dynamic repair checkpoint frozen Harness hash does not match")
            state = RepairState(str(checkpoint["state"]))
            state_trace = [str(value) for value in checkpoint["state_trace"]]
            candidate_source = str(checkpoint["candidate_source"])
            repair_count = int(checkpoint["repair_count"])
            model_call_count = int(checkpoint.get("model_call_count", 0))
            model_tokens_used = int(checkpoint.get("model_tokens_used", 0))
            model_call_audits = list(checkpoint.get("model_call_audits", []))
            seen_source_hashes = set(checkpoint["seen_source_hashes"])
            repair_requests = list(checkpoint["repair_requests"])
            repair_responses = list(checkpoint["repair_responses"])
            iterations = list(checkpoint["iterations"])
            final_reason = str(checkpoint.get("final_reason") or "unknown")
            if state not in {
                RepairState.REPAIR,
                RepairState.ACCEPTED,
                RepairState.BUDGET_EXHAUSTED,
                RepairState.UNSUPPORTED,
                RepairState.FAILED,
            }:
                raise RunnerError(
                    f"dynamic repair checkpoint cannot resume from state {state.value}"
                )

        if state in {
            RepairState.ACCEPTED,
            RepairState.BUDGET_EXHAUSTED,
            RepairState.UNSUPPORTED,
            RepairState.FAILED,
        }:
            metadata.update(
                {
                    "repair_status": state.value,
                    "repair_iterations": repair_count,
                    "repair_state_trace": state_trace,
                    "repairer_version": self.repairer.version,
                    "stop_reason": final_reason,
                    "repair_resumed_from_checkpoint": True,
                }
            )
            _write_json(metadata_path, metadata)
            return BinOracleResult(
                candidate_code=candidate_source,
                summary=(
                    f"BinOracle restored terminal dynamic repair state {state.value} "
                    "from a verified checkpoint."
                ),
                metadata=metadata,
            )

        while True:
            move(RepairState.COMPILE)
            iteration_index = len(iterations)
            candidate_dir = stage_dir / "candidate" / f"iteration-{iteration_index:02d}"
            result = self._differential_run(
                base_result=base_result,
                facts=facts,
                target_function=target_function,
                initial_code=initial_code,
                optimization=optimization,
                artifact_dir=artifact_dir,
                stage_dir=stage_dir,
                candidate_code=candidate_source,
                candidate_dir=candidate_dir,
            )
            differential = json.loads(
                (stage_dir / "differential_summary.json").read_text(encoding="utf-8")
            )
            compile_manifest = json.loads(
                (candidate_dir / "candidate_compile.json").read_text(encoding="utf-8")
            )
            gate_manifest_path = candidate_dir / "candidate_compile_gate.json"
            repair_diagnostics_manifest = (
                json.loads(gate_manifest_path.read_text(encoding="utf-8"))
                if gate_manifest_path.is_file()
                and differential.get("candidate_compile_gate") is False
                else compile_manifest
            )
            if differential.get("candidate_compile"):
                move(RepairState.LINK)
                if differential.get("candidate_link"):
                    move(RepairState.DIFFERENTIAL)
            evidence = _read_jsonl(stage_dir / "evidence_packages.jsonl")
            differences = _read_jsonl(stage_dir / "differences.jsonl")
            iterations.append(
                {
                    "schema_version": "binoracle.dynamic-repair-iteration.v1",
                    "iteration": iteration_index,
                    "candidate_source_sha256": hashlib.sha256(
                        candidate_source.encode("utf-8")
                    ).hexdigest(),
                    "candidate_dir": str(candidate_dir.relative_to(stage_dir)),
                    "differential": differential,
                    "compile_gate": (
                        repair_diagnostics_manifest
                        if differential.get("candidate_compile_gate") is not None
                        else None
                    ),
                    "differences": differences,
                    "evidence_packages": evidence,
                }
            )
            _write_json(
                repair_dir / f"iteration-{iteration_index:02d}.json",
                iterations[-1],
            )
            if hashlib.sha256(harness_path.read_bytes()).hexdigest() != frozen_file_hash:
                if state == RepairState.DIFFERENTIAL:
                    move(RepairState.FAILED)
                elif state in {RepairState.COMPILE, RepairState.LINK}:
                    move(RepairState.FAILED)
                final_reason = "frozen_harness_mutated"
                break

            if differential.get("differential_pass"):
                move(RepairState.FULL_REGRESSION)
                move(RepairState.ACCEPTED)
                final_reason = "full_frozen_regression_passed"
                break

            if state == RepairState.DIFFERENTIAL and evidence:
                move(RepairState.MINIMIZE)
                move(RepairState.REPAIR)
            elif state in {RepairState.COMPILE, RepairState.LINK, RepairState.DIFFERENTIAL}:
                move(RepairState.REPAIR)
            else:
                move(RepairState.FAILED)
                final_reason = "unexpected_repair_state"
                break

            if repair_count >= self.max_repair_iterations:
                move(RepairState.BUDGET_EXHAUSTED)
                final_reason = "repair_iteration_budget_exhausted"
                break

            request = RepairRequest(
                sample_id=sample_id,
                candidate_source=candidate_source,
                compile_diagnostics=str(repair_diagnostics_manifest.get("stderr") or ""),
                frozen_harness_hash=frozen_content_hash,
                evidence_packages=tuple(evidence[:3]),
                allowed_edit_scope=("public_declarations", "target_function"),
                iteration=repair_count,
                remaining_budget=RepairBudget(
                    iterations_remaining=self.max_repair_iterations - repair_count,
                    executions_remaining=max(
                        0,
                        self.runner.max_executions
                        - int(result.metadata.get("executions", 0)),
                    ),
                    model_calls_remaining=max(
                        0, self.max_repair_model_calls - model_call_count
                    ),
                    tokens_remaining=max(0, self.max_repair_tokens - model_tokens_used),
                ),
            )
            response = self.repairer.repair(
                request,
                binary_facts=facts.to_dict(),
            )
            model_audit = self.repairer.pop_audit_metadata()
            if model_audit is not None:
                model_call_count += 1
                usage = model_audit.get("usage") or {}
                if isinstance(usage, dict):
                    model_tokens_used += int(usage.get("total_tokens") or 0)
                model_call_audits.append(model_audit)
                _write_jsonl(stage_dir / "repair_model_calls.jsonl", model_call_audits)
            repair_requests.append(request.to_dict())
            repair_responses.append(response.to_dict())
            _write_jsonl(stage_dir / "repair_requests.jsonl", repair_requests)
            _write_jsonl(stage_dir / "repair_responses.jsonl", repair_responses)
            if response.abstain:
                move(RepairState.FAILED)
                final_reason = "repairer_abstained"
                break
            revised_hash = hashlib.sha256(
                response.revised_source.encode("utf-8")
            ).hexdigest()
            if revised_hash in seen_source_hashes:
                move(RepairState.FAILED)
                final_reason = "duplicate_repair_candidate"
                break
            seen_source_hashes.add(revised_hash)
            candidate_source = response.revised_source
            repair_count += 1
            final_reason = "repair_candidate_pending_full_regression"
            save_checkpoint()

        save_checkpoint()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata.update(
            {
                "repair_status": state.value,
                "repair_iterations": repair_count,
                "repair_state_trace": state_trace,
                "repairer_version": self.repairer.version,
                "repairer_kind": self.repairer_kind,
                "repair_model_calls": model_call_count,
                "repair_model_tokens": model_tokens_used,
                "stop_reason": final_reason,
                "harness_mutated": False,
            }
        )
        if repair_count:
            metadata["implemented_stages"] = [
                *metadata.get("implemented_stages", []),
                "deterministic_evidence_guided_repair",
                "full_frozen_harness_regression",
            ]
        _write_json(metadata_path, metadata)
        summary = {
            "schema_version": "binoracle.dynamic-repair-summary.v1",
            "status": state.value,
            "reason": final_reason,
            "repairer_version": self.repairer.version,
            "repairer_kind": self.repairer_kind,
            "repair_model_calls": model_call_count,
            "repair_model_tokens": model_tokens_used,
            "repair_iterations": repair_count,
            "candidate_iterations": len(iterations),
            "state_trace": state_trace,
            "frozen_harness_hash": frozen_content_hash,
            "harness_mutated": False,
            "final_candidate_sha256": hashlib.sha256(
                candidate_source.encode("utf-8")
            ).hexdigest(),
            "iterations": iterations,
        }
        _write_json(stage_dir / "repair_summary.json", summary)
        return BinOracleResult(
            candidate_code=candidate_source,
            summary=(
                f"BinOracle dynamic repair stopped as {state.value} after "
                f"{repair_count} repair iteration(s): {final_reason}."
            ),
            metadata=metadata,
        )

    def run(
        self,
        *,
        binary_path: Path,
        target_function: str,
        initial_code: str,
        assembly: str,
        assembly_syntax: str = "auto",
        architecture: str,
        optimization: str,
        sample_id: str,
        artifact_dir: Path,
    ) -> BinOracleResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        stage_dir = artifact_dir / "binoracle"
        stage_dir.mkdir(parents=True, exist_ok=True)
        facts = extract_binary_facts(
            binary_path,
            target_function=target_function,
            require_relocatable=self.require_relocatable,
        )
        if architecture.lower().replace("-", "_") not in {"x86_64", "amd64"}:
            raise UnsupportedSample(
                "unsupported_architecture", f"request architecture is unsupported: {architecture}"
            )
        self._write_binary_artifacts(stage_dir, facts)
        if self.mode == "static_passthrough":
            return self._static_run(
                facts=facts,
                initial_code=initial_code,
                assembly=assembly,
                assembly_syntax=assembly_syntax,
                optimization=optimization,
                sample_id=sample_id,
                artifact_dir=artifact_dir,
                stage_dir=stage_dir,
                started=started,
            )
        if self.mode == "dynamic_audit":
            return self._dynamic_run(
                facts=facts,
                binary_path=binary_path,
                target_function=target_function,
                initial_code=initial_code,
                optimization=optimization,
                sample_id=sample_id,
                artifact_dir=artifact_dir,
                stage_dir=stage_dir,
                started=started,
            )
        result = self._contract_probe_run(
            facts=facts,
            binary_path=binary_path,
            target_function=target_function,
            initial_code=initial_code,
            assembly=assembly,
            assembly_syntax=assembly_syntax,
            optimization=optimization,
            sample_id=sample_id,
            artifact_dir=artifact_dir,
            stage_dir=stage_dir,
            started=started,
        )
        if self.mode not in {"differential", "dynamic_repair"}:
            return result
        if self.mode == "differential":
            return self._differential_run(
                base_result=result,
                facts=facts,
                target_function=target_function,
                initial_code=initial_code,
                optimization=optimization,
                artifact_dir=artifact_dir,
                stage_dir=stage_dir,
            )
        return self._dynamic_repair_run(
            base_result=result,
            facts=facts,
            target_function=target_function,
            initial_code=initial_code,
            optimization=optimization,
            sample_id=sample_id,
            artifact_dir=artifact_dir,
            stage_dir=stage_dir,
        )

    def close(self) -> None:
        return None


__all__ = ["BinOracleEngine", "BinOracleResult", "RunnerError", "UnsupportedSample"]
