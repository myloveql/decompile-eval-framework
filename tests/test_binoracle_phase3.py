from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from plugins.binoracle.auditor import freeze_harness_manifest
from plugins.binoracle.candidate import CandidateCompiler
from plugins.binoracle.contract_v2 import ContractGraphV2
from plugins.binoracle.holdout import commit_holdout
from plugins.binoracle.phase3 import (
    create_phase3_baseline,
    replay_phase3_baseline,
    verify_phase3_baseline,
)
from plugins.binoracle.phase3_reporting import summarize_phase3_differential
from plugins.binoracle.probes import generate_probe_plan
from plugins.binoracle.repair import (
    DeterministicRepairer,
    HybridRepairer,
    OpenAIRepairer,
    RepairBudget,
    RepairProtocolError,
    RepairRequest,
    RepairResponse,
    RepairState,
    validate_transition,
)
from plugins.binoracle.security import (
    inspect_candidate_source,
    sanitized_subprocess_environment,
)


class BinOraclePhase3Tests(unittest.TestCase):
    def _frozen_artifact(self, root: Path) -> Path:
        artifact = root / "run" / "artifacts" / "dataset" / "backend" / "sample"
        stage = artifact / "binoracle"
        contract = ContractGraphV2.from_dict(
            {
                "schema_version": "binoracle.contract.v2",
                "contract_id": "K0",
                "sample_id": "sample:O0",
                "abi": "sysv-x86_64",
                "arguments": [],
                "objects": [],
                "return": {
                    "kind_candidates": ["void"],
                    "observable": False,
                    "confidence": 1.0,
                    "evidence_ids": ["insn:ret"],
                },
                "globals": [],
                "dependencies": [],
                "preconditions": [],
                "observables": [],
                "unsupported_reasons": [],
                "evidence_ids": ["insn:ret"],
                "confidence": 1.0,
            }
        )
        probes = generate_probe_plan(contract, base_seed=1, max_executions=4, repetitions=1)
        holdout = commit_holdout(contract, probe_seed=1, max_executions=2, repetitions=1)
        policy = {"schema_version": 1, "compare_return": False, "compare_globals": True}
        manifest = freeze_harness_manifest(
            contract=contract,
            probes=probes,
            observation_policy=policy,
            runner_version="runner-test",
            target_function="target",
            probe_seed=1,
            resource_limits={"execution_timeout_ms": 100, "max_executions": 4},
            holdout_probes=holdout.probes,
            holdout=holdout.commitment,
        )
        contract_dir = stage / "contracts" / "K0"
        contract_dir.mkdir(parents=True)
        artifact.joinpath("binoracle_public_request.json").write_text(
            json.dumps({"sample_id": "sample:O0", "optimization": "O0"}), encoding="utf-8"
        )
        artifact.joinpath("binoracle_metadata.json").write_text(
            json.dumps(
                {
                    "sample_id": "sample:O0",
                    "optimization": "O0",
                    "harness_frozen": True,
                    "contract_selection_status": "audit_accepted_frozen",
                    "candidate_compile": True,
                    "candidate_link": True,
                    "differential_pass": False,
                    "executions": 8,
                }
            ),
            encoding="utf-8",
        )
        stage.joinpath("selected_contract.json").write_text(
            json.dumps(contract.to_dict()), encoding="utf-8"
        )
        stage.joinpath("observation_policy.json").write_text(json.dumps(policy), encoding="utf-8")
        stage.joinpath("harness_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        contract_dir.joinpath("probe_plan.jsonl").write_text(
            "".join(json.dumps(probe.to_dict()) + "\n" for probe in probes), encoding="utf-8"
        )
        contract_dir.joinpath("original_observations.jsonl").write_text(
            "".join(json.dumps({"status": "returned"}) + "\n" for _ in probes), encoding="utf-8"
        )
        contract_dir.joinpath("holdout_probe_plan.jsonl").write_text(
            "".join(json.dumps(probe.to_dict()) + "\n" for probe in holdout.probes),
            encoding="utf-8",
        )
        contract_dir.joinpath("holdout_observations.jsonl").write_text(
            "".join(json.dumps({"status": "returned"}) + "\n" for _ in holdout.probes),
            encoding="utf-8",
        )
        contract_dir.joinpath("original_runner.x").write_bytes(b"runner")
        stage.joinpath("differential_summary.json").write_text(
            json.dumps(
                {
                    "candidate_compile": True,
                    "candidate_link": True,
                    "differential_pass": False,
                    "tests_total": 4,
                    "tests_passed": 3,
                    "differences": 1,
                    "difference_kinds": {"memory": 1},
                    "evidence_packages": 1,
                    "minimized_counterexamples": 1,
                }
            ),
            encoding="utf-8",
        )
        return artifact

    def test_phase3_baseline_cross_checks_frozen_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = self._frozen_artifact(root)
            output = root / "phase3_baseline_manifest.json"
            manifest = create_phase3_baseline([root / "run"], output_path=output)
            self.assertTrue(verify_phase3_baseline(manifest))
            self.assertEqual(manifest["valid_frozen_harnesses"], 1)
            self.assertEqual(manifest["invalid_frozen_harnesses"], 0)

            artifact.joinpath("binoracle", "observation_policy.json").write_text(
                json.dumps({"compare_return": True}), encoding="utf-8"
            )
            invalid = create_phase3_baseline([root / "run"], output_path=output)
            self.assertEqual(invalid["invalid_frozen_harnesses"], 1)
            self.assertIn(
                "observation_policy_hash", invalid["entries"][0]["failure_reasons"]
            )

            invalid["content_hash"] = "0" * 64
            output.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "content hash is invalid"):
                replay_phase3_baseline(output, output_path=root / "replay.json")

    def test_phase3_baseline_rejects_missing_or_changed_holdout_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = self._frozen_artifact(root)
            output = root / "phase3_baseline_manifest.json"
            valid = create_phase3_baseline([root / "run"], output_path=output)
            self.assertEqual(valid["valid_frozen_harnesses"], 1)

            holdout_plan = artifact / "binoracle" / "contracts" / "K0" / "holdout_probe_plan.jsonl"
            holdout_plan.unlink()
            invalid = create_phase3_baseline([root / "run"], output_path=output)
            self.assertIn("holdout_probe_plan_hash", invalid["entries"][0]["failure_reasons"])
            self.assertIn("holdout_probe_count", invalid["entries"][0]["failure_reasons"])

    def test_phase3_differential_report_keeps_fixed_denominator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._frozen_artifact(root)
            report = summarize_phase3_differential(root / "run")
            overall = report["overall"]
            self.assertEqual(overall["total"], 1)
            self.assertEqual(overall["candidate_compile_rate_fixed_denominator"], 1.0)
            self.assertEqual(overall["differential_pass_rate_fixed_denominator"], 0.0)
            self.assertEqual(
                overall["differential_pass_rate_fixed_denominator_ci95"][0], 0.0
            )
            self.assertEqual(overall["difference_kind_counts"], {"memory": 1})

    def test_phase3_report_keeps_pre_artifact_framework_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._frozen_artifact(root)
            result = {
                "sample_id": "sample:unsupported:O1",
                "source_group_id": "group:unsupported",
                "optimization": "O1",
                "reason": "binoracle_automatic_contract_no_runnable_candidate",
            }
            (root / "run" / "results.jsonl").write_text(
                json.dumps(result) + "\n", encoding="utf-8"
            )
            report = summarize_phase3_differential(root / "run")
            self.assertEqual(report["overall"]["total"], 2)
            self.assertEqual(report["overall"]["status_counts"]["unsupported"], 1)

    def test_repair_protocol_rejects_illegal_transition_and_unproven_edit(self):
        with self.assertRaisesRegex(RepairProtocolError, "illegal repair state transition"):
            validate_transition(RepairState.INITIAL, RepairState.ACCEPTED)
        with self.assertRaisesRegex(RepairProtocolError, "requires rationale"):
            RepairResponse("int target(void) { return 0; }", (), (), (), False)
        with self.assertRaisesRegex(RepairProtocolError, "contains private fields"):
            RepairRequest(
                sample_id="sample:O1",
                candidate_source="void target(void) {}",
                compile_diagnostics="",
                frozen_harness_hash="a" * 64,
                evidence_packages=({"ground_truth": "private"},),
                allowed_edit_scope=("target_function",),
                iteration=0,
                remaining_budget=RepairBudget(1, 1),
            )

    def test_deterministic_repair_ignores_unrelated_unknown_global(self):
        request = RepairRequest(
            sample_id="sample:O1",
            candidate_source="void target(void) { return; }",
            compile_diagnostics="error: ‘invented’ undeclared",
            frozen_harness_hash="a" * 64,
            evidence_packages=(),
            allowed_edit_scope=("public_declarations",),
            iteration=0,
            remaining_budget=RepairBudget(2, 100),
        )
        abstained = DeterministicRepairer().repair(
            request,
            binary_facts={"global_objects": []},
        )
        self.assertTrue(abstained.abstain)

    def test_deterministic_repair_abstains_for_width_only_global_fact(self):
        request = RepairRequest(
            sample_id="sample:O1",
            candidate_source="void target(long x) { CM = CM - x; }",
            compile_diagnostics="error: ‘CM’ undeclared",
            frozen_harness_hash="a" * 64,
            evidence_packages=(),
            allowed_edit_scope=("public_declarations", "target_function"),
            iteration=0,
            remaining_budget=RepairBudget(2, 100),
        )
        response = DeterministicRepairer().repair(
            request,
            binary_facts={"global_objects": [{"name": "CM", "size": 8}]},
        )
        self.assertTrue(response.abstain)
        self.assertEqual(response.rationale_codes, ("insufficient_public_evidence",))

        evidenced = DeterministicRepairer().repair(
            request,
            binary_facts={
                "global_objects": [
                    {
                        "name": "CM",
                        "size": 8,
                        "public_c_declaration": "extern size_t CM;",
                    }
                ]
            },
        )
        self.assertFalse(evidenced.abstain)
        self.assertTrue(evidenced.revised_source.startswith("extern size_t CM;"))

    def test_candidate_compile_gate_rejects_wrapper_conflict(self):
        with tempfile.TemporaryDirectory() as temporary:
            compiler = CandidateCompiler(
                {
                    "candidate_compile_gate_enabled": True,
                    "candidate_compile_gate_prelude": "extern size_t CM;",
                }
            )
            gated = compiler.compile_gate(
                code="void target(void) { CM++; } extern int CM;",
                function_name="target",
                optimization="O0",
                stage_dir=Path(temporary),
            )
            self.assertIsNotNone(gated)
            assert gated is not None
            self.assertFalse(gated.success)
            self.assertTrue(gated.manifest["compile_gate"]["enabled"])

    def test_candidate_compile_gate_requires_public_declarations(self):
        with self.assertRaisesRegex(ValueError, "candidate_compile_gate_prelude"):
            CandidateCompiler({"candidate_compile_gate_enabled": True})

        class FakeResponse:
            id = "resp_test"
            status = "completed"
            usage = {"input_tokens": 100, "output_tokens": 30, "total_tokens": 130}
            output_text = json.dumps(
                {
                    "revised_source": "long target(long x) { return x + 1; }",
                    "rationale_codes": ["fix_observed_return_delta"],
                    "evidence_ids": ["evidence-1"],
                    "changed_regions": ["target_function"],
                    "abstain": False,
                }
            )

        class FakeResponses:
            def __init__(self):
                self.params = None

            def create(self, **params):
                self.params = params
                return FakeResponse()

        class FakeClient:
            def __init__(self):
                self.responses = FakeResponses()

        request = RepairRequest(
            sample_id="sample:O2",
            candidate_source="long target(long x) { return x; }",
            compile_diagnostics="",
            frozen_harness_hash="b" * 64,
            evidence_packages=({"evidence_id": "evidence-1", "difference": {}},),
            allowed_edit_scope=("target_function",),
            iteration=0,
            remaining_budget=RepairBudget(1, 20, 1, 512),
        )
        client = FakeClient()
        model = OpenAIRepairer(model="test-model", max_output_tokens=256, client=client)
        response = HybridRepairer(DeterministicRepairer(), model).repair(
            request, binary_facts={"global_objects": []}
        )
        self.assertFalse(response.abstain)
        self.assertEqual(response.evidence_ids, ("evidence-1",))
        self.assertFalse(client.responses.params["store"])
        self.assertTrue(client.responses.params["text"]["format"]["strict"])
        self.assertNotIn("binary_facts", client.responses.params["input"])
        audit = model.pop_audit_metadata()
        self.assertEqual(audit["usage"]["total_tokens"], 130)

    def test_openai_repairer_abstains_without_model_budget(self):
        request = RepairRequest(
            sample_id="sample:O0",
            candidate_source="void target(void) {}",
            compile_diagnostics="error",
            frozen_harness_hash="c" * 64,
            evidence_packages=(),
            allowed_edit_scope=("target_function",),
            iteration=0,
            remaining_budget=RepairBudget(1, 20, 0, 0),
        )
        response = OpenAIRepairer(model="unused").repair(request, binary_facts={})
        self.assertTrue(response.abstain)
        self.assertEqual(response.rationale_codes, ("model_call_budget_exhausted",))

    def test_candidate_security_blocks_escape_primitives_and_clears_credentials(self):
        attacks = (
            '#include "/etc/passwd"\nvoid target(void) {}',
            'void target(void) { system("id"); }',
            'void target(void) { __asm__("syscall"); }',
            'void target(void) { fopen("../secret", "r"); }',
            'void target(void) __attribute__((constructor));',
        )
        for attack in attacks:
            with self.subTest(attack=attack):
                self.assertFalse(inspect_candidate_source(attack).allowed)
        self.assertTrue(
            inspect_candidate_source("unsigned long target(unsigned long x) { return x + 1; }").allowed
        )
        old = os.environ.get("OPENAI_API_KEY")
        try:
            os.environ["OPENAI_API_KEY"] = "must-not-leak"
            self.assertNotIn("OPENAI_API_KEY", sanitized_subprocess_environment())
        finally:
            if old is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = old

        with tempfile.TemporaryDirectory() as temporary:
            build = CandidateCompiler({}).compile(
                code='void target(void) { system("id"); }',
                function_name="target",
                optimization="O0",
                stage_dir=Path(temporary),
            )
            self.assertFalse(build.success)
            self.assertEqual(build.manifest["command"], [])
            self.assertFalse(build.manifest["security_policy"]["allowed"])


if __name__ == "__main__":
    unittest.main()
