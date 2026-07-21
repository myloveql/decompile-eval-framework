from __future__ import annotations

import unittest

from plugins.binoracle.active_probes import (
    generate_failure_directed_probes,
    should_stop_active_probing,
)
from plugins.binoracle.ambiguity import (
    equivalent_if_no_disagreement,
    generate_discriminative_probes,
)
from plugins.binoracle.capability import assess_capability
from plugins.binoracle.differential import compare_observations
from plugins.binoracle.contract_v2 import ContractGraphV2, ContractValidationError
from plugins.binoracle.holdout import commit_holdout
from plugins.binoracle.llm_proposals import ContractProposal, ProbeIntent, ProposalValidationError
from plugins.binoracle.protocol import InputCase, KnownContract, ProtocolError
from plugins.binoracle.resolution import HarnessResolutionState, ResolutionBudget, ResolutionStatus


def contract_payload() -> dict:
    return {
        "schema_version": "binoracle.contract.v2",
        "sample_id": "phase4:O0",
        "contract_id": "K4",
        "abi": "sysv-x86_64",
        "arguments": [
            {"slot": 0, "register": "RDI", "kind_candidates": ["integer"], "confidence": 1.0, "evidence_ids": ["i:0"]},
            {"slot": 3, "register": "RCX", "kind_candidates": ["pointer"], "object_ref": "obj0", "confidence": 1.0, "evidence_ids": ["i:1"]},
        ],
        "objects": [{"object_id": "obj0", "argument_slot": "RCX", "min_size": 8, "alignment": 1, "evidence_ids": ["i:1"]}],
        "return": {"kind_candidates": ["void"], "observable": False, "confidence": 1.0, "evidence_ids": ["i:2"]},
        "globals": [], "dependencies": [{"name": "puts"}], "preconditions": [], "observables": [],
        "unsupported_reasons": [], "confidence": 1.0, "evidence_ids": ["i:0"],
    }


class BinOraclePhase4Tests(unittest.TestCase):
    def test_six_slot_contract_and_stub_capability(self):
        contract = ContractGraphV2.from_dict(contract_payload())
        self.assertEqual(contract.arguments[1].register, "RCX")
        report = assess_capability(contract)
        self.assertEqual(report.status, "supported_with_stub")

    def test_unknown_dependency_remains_fail_closed(self):
        payload = contract_payload()
        payload["dependencies"] = [{"name": "socket"}]
        self.assertEqual(assess_capability(ContractGraphV2.from_dict(payload)).status, "unsupported")

    def test_relation_validation_rejects_unknown_object(self):
        payload = contract_payload()
        payload["relations"] = [{"kind": "no_alias", "left": "obj0", "right": "missing"}]
        with self.assertRaises(ContractValidationError):
            ContractGraphV2.from_dict(payload)

    def test_length_relation_enforced_by_input_protocol(self):
        contract = KnownContract.from_dict({
            "contract_id": "K", "arguments": [{"slot": "RDI", "kind": "integer"}, {"slot": "RSI", "kind": "pointer", "object_ref": "obj0"}],
            "return": {"kind": "void"}, "objects": [{"object_id": "obj0", "min_size": 4, "alignment": 1}],
            "relations": [{"kind": "length_within", "length_slot": "RDI", "object_ref": "obj0"}],
        })
        with self.assertRaises(ProtocolError):
            InputCase.from_dict({"contract_id": "K", "gpr": {"RDI": 5, "RSI": {"object_ref": "obj0"}}, "objects": {"obj0": {"size": 4, "bytes_hex": "00000000"}}, "globals": {}}, contract=contract)

    def test_runner_contract_canonicalizes_must_alias_objects(self):
        payload = {
            "schema_version": "binoracle.contract.v2", "sample_id": "alias:O0", "contract_id": "K-alias", "abi": "sysv-x86_64",
            "arguments": [
                {"slot": 0, "register": "RDI", "kind_candidates": ["pointer"], "object_ref": "left", "confidence": 1.0, "evidence_ids": []},
                {"slot": 1, "register": "RSI", "kind_candidates": ["pointer"], "object_ref": "right", "confidence": 1.0, "evidence_ids": []},
            ],
            "objects": [
                {"object_id": "left", "argument_slot": "RDI", "min_size": 4, "alignment": 1, "read_ranges": [], "write_ranges": [], "evidence_ids": []},
                {"object_id": "right", "argument_slot": "RSI", "min_size": 8, "alignment": 1, "read_ranges": [], "write_ranges": [], "evidence_ids": []},
            ],
            "return": {"kind_candidates": ["void"], "observable": False, "confidence": 1.0, "evidence_ids": []},
            "relations": [{"kind": "must_alias", "left": "left", "right": "right"}],
            "globals": [], "dependencies": [], "unsupported_reasons": [], "confidence": 1.0, "evidence_ids": [],
        }
        runner = ContractGraphV2.from_dict(payload).to_runner_contract()
        self.assertEqual([item["object_ref"] for item in runner.arguments], ["left", "left"])
        self.assertEqual(runner.objects, ({"object_id": "left", "min_size": 8, "alignment": 1},))
        case = InputCase.from_dict({"contract_id": "K-alias", "gpr": {"RDI": {"object_ref": "left"}, "RSI": {"object_ref": "left"}}, "objects": {"left": {"size": 8, "bytes_hex": "00" * 8}}, "globals": {}}, contract=runner)
        self.assertEqual(case.gpr["RDI"], case.gpr["RSI"])

    def test_nonzero_fixed_offset_alias_is_rejected_without_runner_support(self):
        payload = contract_payload()
        payload["arguments"] = [
            {"slot": 0, "register": "RDI", "kind_candidates": ["pointer"], "object_ref": "left", "confidence": 1.0, "evidence_ids": []},
            {"slot": 1, "register": "RSI", "kind_candidates": ["pointer"], "object_ref": "right", "confidence": 1.0, "evidence_ids": []},
        ]
        payload["objects"] = [
            {"object_id": "left", "argument_slot": "RDI", "min_size": 4, "alignment": 1, "read_ranges": [], "write_ranges": [], "evidence_ids": []},
            {"object_id": "right", "argument_slot": "RSI", "min_size": 4, "alignment": 1, "read_ranges": [], "write_ranges": [], "evidence_ids": []},
        ]
        payload["relations"] = [{"kind": "fixed_offset_alias", "left": "left", "right": "right", "offset": 1}]
        with self.assertRaisesRegex(ContractValidationError, "non-zero fixed_offset_alias"):
            ContractGraphV2.from_dict(payload)

    def test_holdout_is_deterministic_and_committed(self):
        contract = ContractGraphV2.from_dict(contract_payload())
        one = commit_holdout(contract, probe_seed=7, max_executions=4, repetitions=1)
        two = commit_holdout(contract, probe_seed=7, max_executions=4, repetitions=1)
        self.assertEqual(one.commitment, two.commitment)
        self.assertEqual(one.probes, two.probes)

    def test_resolution_transitions_are_explicit(self):
        state = HarnessResolutionState("phase4", budget=ResolutionBudget(2, 10, 1.0))
        state = state.transition(ResolutionStatus.STATIC_INFERRED)
        state = state.transition(ResolutionStatus.CAPABILITY_CHECKED)
        state = state.transition(ResolutionStatus.PROBED)
        self.assertEqual(state.round_index, 1)
        with self.assertRaises(ValueError):
            state.transition(ResolutionStatus.STATIC_INFERRED)

    def test_active_probe_stop_rules(self):
        self.assertEqual(should_stop_active_probing(no_information_rounds=2, risk_upper_bound=0, risk_limit=.1, budget_exhausted=False), "no_new_information")
        self.assertEqual(should_stop_active_probing(no_information_rounds=0, risk_upper_bound=.2, risk_limit=.1, budget_exhausted=False), "risk_limit_exceeded")

    def test_llm_proposals_require_public_evidence_only(self):
        proposal = ContractProposal.from_dict({"proposed_contract": {"arguments": []}, "evidence_ids": ["e1"], "confidence": .5}, known_evidence_ids=["e1"])
        self.assertEqual(proposal.evidence_ids, ("e1",))
        with self.assertRaises(ProposalValidationError):
            ProbeIntent.from_dict({"strategy": "safe_neighborhood", "rationale": "x", "evidence_ids": ["e1"], "confidence": .1, "ground_truth": "forbidden"}, known_evidence_ids=["e1"])

    def test_external_events_are_differentially_observable(self):
        difference = compare_observations(
            "P0",
            {"status": "returned", "objects": {}, "globals": {}, "external_events": [{"name": "read", "count": 1}]},
            {"status": "returned", "objects": {}, "globals": {}, "external_events": []},
            compare_return=False,
        )
        self.assertEqual(difference.kinds, ("external_event",))

    def test_failure_directed_probes_pick_strategy_from_reason_codes(self):
        payload = {
            "schema_version": "binoracle.contract.v2",
            "sample_id": "phase4:O0",
            "contract_id": "K5",
            "abi": "sysv-x86_64",
            "arguments": [
                {"slot": 0, "register": "RDI", "kind_candidates": ["integer"], "confidence": 1.0, "evidence_ids": ["i:0"]},
            ],
            "objects": [],
            "return": {"kind_candidates": ["integer"], "observable": True, "confidence": 1.0, "evidence_ids": ["i:2"]},
            "globals": [], "dependencies": [], "unsupported_reasons": [], "confidence": 1.0, "evidence_ids": ["i:0"],
        }
        contract = ContractGraphV2.from_dict(payload)
        boundary = generate_failure_directed_probes(
            contract, ["effect_below_threshold"], base_seed=2, round_index=1, max_executions=4, repetitions=1
        )
        self.assertEqual(boundary.strategy, "effect_boundary")
        self.assertIn("effect_below_threshold", boundary.reason_codes)
        self.assertGreater(len(boundary.probes), 0)

    def test_discriminative_probes_are_bounded_and_safe(self):
        candidate_one = ContractGraphV2.from_dict(_integer_contract("A1"))
        candidate_two = ContractGraphV2.from_dict(_integer_contract("A2"))
        probes = generate_discriminative_probes(
            [candidate_one, candidate_two], base_seed=3, max_executions=4, repetitions=1
        )
        self.assertGreater(len(probes), 0)
        self.assertLessEqual(len(probes), 4)
        self.assertTrue(all(probe.expected_safe for probe in probes))

    def test_equivalence_class_emits_unidentifiable_status(self):
        candidate_one = ContractGraphV2.from_dict(_integer_contract("A1"))
        candidate_two = ContractGraphV2.from_dict(_integer_contract("A2"))
        equivalence = equivalent_if_no_disagreement(
            [candidate_one, candidate_two], safe_probe_count=3
        )
        record = equivalence.to_dict()
        self.assertEqual(record["status"], "unidentifiable_from_binary")
        self.assertEqual(set(equivalence.contract_ids), {"A1", "A2"})

    def test_rejected_resolution_can_transition_to_unverified_or_loop(self):
        state = HarnessResolutionState("phase4", budget=ResolutionBudget(3, 10, 30.0))
        state = state.transition(ResolutionStatus.STATIC_INFERRED)
        state = state.transition(ResolutionStatus.CAPABILITY_CHECKED)
        state = state.transition(ResolutionStatus.PROBED)
        state = state.transition(
            ResolutionStatus.RETRYABLE_REJECTED,
            reasons=["effect_below_threshold"],
            next_action="failure_directed_probe",
        )
        unverified = state.transition(
            ResolutionStatus.UNVERIFIED, reasons=["no_new_information"], next_action=None
        )
        self.assertEqual(unverified.status.value, "unverified")
        looping = state.transition(
            ResolutionStatus.PROBED, next_action="audit_exploration"
        )
        self.assertEqual(looping.round_index, 2)

    def test_ambiguous_resolution_can_emit_equivalence_class(self):
        state = HarnessResolutionState("phase4", budget=ResolutionBudget(3, 10, 30.0))
        state = state.transition(ResolutionStatus.STATIC_INFERRED)
        state = state.transition(ResolutionStatus.CAPABILITY_CHECKED)
        state = state.transition(ResolutionStatus.PROBED)
        state = state.transition(
            ResolutionStatus.AMBIGUOUS,
            reasons=["score_margin_below_threshold"],
            next_action="discriminate",
        )
        equivalence = state.transition(
            ResolutionStatus.BEHAVIORAL_EQUIVALENCE_CLASS,
            reasons=["ambiguity_not_distinguishable_from_binary"],
            next_action=None,
        )
        record = equivalence.to_dict()
        self.assertTrue(record["terminal"])
        self.assertEqual(record["status"], "behavioral_equivalence_class")


def _integer_contract(contract_id: str) -> dict:
    return {
        "schema_version": "binoracle.contract.v2",
        "sample_id": "phase4:O0",
        "contract_id": contract_id,
        "abi": "sysv-x86_64",
        "arguments": [
            {"slot": 0, "register": "RDI", "kind_candidates": ["integer"], "confidence": 1.0, "evidence_ids": ["i:0"]},
        ],
        "objects": [],
        "return": {"kind_candidates": ["integer"], "observable": True, "confidence": 1.0, "evidence_ids": ["i:2"]},
        "globals": [], "dependencies": [], "unsupported_reasons": [], "confidence": 1.0, "evidence_ids": ["i:0"],
    }


if __name__ == "__main__":
    unittest.main()
