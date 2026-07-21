from __future__ import annotations

import json
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from decomp_eval.datasets.exebench import ExeBenchFlatAdapter
from decomp_eval.models import (
    AssemblyInput,
    BinaryInput,
    CanonicalSample,
    DecompileRequest,
    PseudocodeInput,
)
from decomp_eval.runner import EvaluationRunner
from decomp_eval.util import sha256_json
from plugins.binoracle.auditor import (
    AuditThresholds,
    audit_contracts,
    freeze_harness_manifest,
    verify_harness_manifest,
)
from plugins.binoracle.candidates import generate_contract_candidates
from plugins.binoracle.candidate import externalize_candidate
from plugins.binoracle.contract import infer_contract
from plugins.binoracle.contract_v2 import (
    SCHEMA_VERSION,
    ContractGraphV2,
    ContractValidationError,
)
from plugins.binoracle.counterexamples import (
    build_evidence_package,
    minimize_counterexample,
)
from plugins.binoracle.dependencies import classify_dependencies
from plugins.binoracle.differential import compare_observations
from plugins.binoracle.ir import parse_assembly
from plugins.binoracle.privacy import find_private_metadata_paths
from plugins.binoracle.probes import generate_probe_plan, score_contract
from plugins.binoracle.protocol import InputCase, KnownContract, normalize_observation
from plugins.binoracle.selection import build_group_selection_manifest
from plugins.binoracle.taint import analyze_taint
from plugins.binoracle_backend import BinOracleBackend
from plugins.binoracle_metrics import CandidateCompileMetric, ExecutionCountMetric


PROJECT = Path(__file__).resolve().parents[1]


class BinOracleFixtureDataset:
    plugin_name = "binoracle_fixture"
    default_protocol = "tests.fixtures:FixtureProtocol"

    def __init__(self, config, **kwargs):
        self.dataset_id = config["id"]
        self.binary_path = str(config["binary_path"])
        self.evaluation_protocol = None

    def iter_samples(self):
        yield CanonicalSample(
            dataset_id=self.dataset_id,
            split="test",
            sample_id="binoracle-fixture:O0",
            source_group_id="binoracle-fixture",
            function_name="answer",
            language="c",
            optimization="O0",
            assembly=AssemblyInput("answer:\n movl $7, %eax\n ret\n", "AT&T", "fixture"),
            content_hash=sha256_json({"fixture": "binoracle"}),
            binary=BinaryInput(
                path=self.binary_path,
                format="ELF-REL",
                architecture="x86_64",
            ),
            pseudocode=PseudocodeInput(
                text="int answer(void) { return 7; }",
                view="ghidra",
                producer="fixture",
            ),
            metadata={"source_type": "fixture"},
            private_payload={"reference": "int answer(void) { return 7; }"},
        )


def _minimal_elf64_rel(path: Path, symbol: str = "target") -> None:
    text = b"\xc3"
    strings = b"\0" + symbol.encode("ascii") + b"\0"
    section_strings = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    text_offset = 64
    strings_offset = text_offset + len(text)
    symbol_offset = 80
    symbol_data = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, 1)
    section_strings_offset = symbol_offset + len(symbol_data)
    section_offset = (section_strings_offset + len(section_strings) + 7) & ~7
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4:7] = bytes((2, 1, 1))
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", bytes(ident), 1, 62, 1, 0, 0,
        section_offset, 0, 64, 0, 0, 64, 5, 4,
    )
    sections = [
        bytes(64),
        struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0, text_offset, len(text), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 7, 2, 0, 0, symbol_offset, len(symbol_data), 3, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 23, 3, 0, 0, section_strings_offset, len(section_strings), 0, 0, 1, 0),
    ]
    data = bytearray(section_offset + 64 * len(sections))
    data[:64] = header
    data[text_offset:text_offset + len(text)] = text
    data[strings_offset:strings_offset + len(strings)] = strings
    data[symbol_offset:symbol_offset + len(symbol_data)] = symbol_data
    data[section_strings_offset:section_strings_offset + len(section_strings)] = section_strings
    for index, section in enumerate(sections):
        start = section_offset + index * 64
        data[start:start + 64] = section
    path.write_bytes(data)


def _request(binary: Path, *, metadata=None) -> DecompileRequest:
    return DecompileRequest(
        dataset_id="fixture",
        split="test",
        sample_id="fixture:void_O0",
        source_group_id="fixture:void",
        function_name="target",
        language="c",
        optimization="O0",
        assembly=AssemblyInput(
            "target:\n    movl %edi, (%rsi)\n    ret\n",
            "GNU assembler AT&T",
            "fixture",
        ),
        metadata=metadata or {"source_type": "fixture"},
        binary=BinaryInput(
            path=str(binary), sha256=None, format="ELF-REL", architecture="x86_64"
        ),
        pseudocode=PseudocodeInput(
            text="void target(int value, int *out) { *out = value; }",
            view="ghidra",
            producer="ghidra",
            version="test",
        ),
    )


class BinOracleBackendTests(unittest.TestCase):
    def test_static_backend_emits_candidate_and_audit_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "target.o"
            _minimal_elf64_rel(binary)
            artifact = root / "artifact"
            backend = BinOracleBackend(
                {
                    "mode": "static_passthrough",
                    "strict_privacy": True,
                    "require_relocatable": True,
                }
            )
            result = backend.decompile(_request(binary), artifact)

            self.assertTrue(result.success, result.log)
            self.assertIn("void target", result.code)
            metadata = json.loads(
                (artifact / "binoracle_metadata.json").read_text(encoding="utf-8")
            )
            policy = json.loads(
                (artifact / "binoracle" / "observation_policy.json").read_text(
                    encoding="utf-8"
                )
            )
            contract = json.loads(
                (artifact / "binoracle" / "selected_contract.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["return_kind"], "void_or_unknown")
            self.assertFalse(policy["compare_return"])
            self.assertEqual(metadata["contract_candidates"], 4)
            self.assertEqual(metadata["contract_selection_status"], "static_unreviewed")
            self.assertEqual(contract["schema_version"], SCHEMA_VERSION)
            self.assertEqual(contract["sample_id"], "fixture:void_O0")
            self.assertEqual(metadata["contract_hash"], ContractGraphV2.from_dict(contract).content_hash)
            self.assertEqual(contract["arguments"][1]["kind_candidates"][0], "pointer")
            self.assertTrue((artifact / "binoracle_public_request.json").is_file())
            self.assertTrue((artifact / "binoracle" / "symbols.json").is_file())
            self.assertTrue((artifact / "binoracle" / "relocations.json").is_file())
            self.assertTrue((artifact / "binoracle" / "dependencies.json").is_file())
            normalized = [
                json.loads(line)
                for line in (artifact / "binoracle" / "normalized_ir.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            taint = json.loads(
                (artifact / "binoracle" / "taint_analysis.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(normalized[0]["mnemonic"], "movl")
            self.assertEqual(taint["schema_version"], "binoracle.taint.v1")
            self.assertIn("RSI", taint["pointer_evidence"])

    def test_invalid_binary_has_stable_failure_classification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "not-elf.o"
            binary.write_bytes(b"not an elf")
            artifact = root / "artifact"
            result = BinOracleBackend({"strict_privacy": True}).decompile(
                _request(binary), artifact
            )
            metadata = json.loads(
                (artifact / "binoracle_metadata.json").read_text(encoding="utf-8")
            )
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "binoracle_unsupported_binary_format")
        self.assertEqual(metadata["unsupported_reason"], result.reason)
        self.assertEqual(metadata["sample_id"], "fixture:void_O0")
        self.assertEqual(metadata["source_group_id"], "fixture:void")
        self.assertEqual(metadata["optimization"], "O0")

    def test_strict_backend_rejects_signature_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "target.o"
            _minimal_elf64_rel(binary)
            result = BinOracleBackend({"strict_privacy": True}).decompile(
                _request(binary, metadata={"signature": ["void", "int *"]}),
                root / "artifact",
            )
            self.assertFalse(result.success)
            self.assertEqual(result.reason, "binoracle_private_metadata_exposed")

    def test_contract_marks_memory_base_as_pointer_and_void_as_unobservable(self):
        contract = infer_contract("target:\n movl %edi, 8(%rsi)\n ret\n")
        self.assertEqual([arg.slot for arg in contract.arguments], ["RDI", "RSI"])
        self.assertEqual(contract.arguments[1].kind_candidates[0], "pointer")
        self.assertEqual(contract.objects[0].min_size, 12)
        self.assertEqual(contract.return_spec.kind, "void_or_unknown")
        self.assertFalse(contract.return_spec.observable)

    def test_contract_ignores_temporary_argument_register_defined_before_use(self):
        contract = infer_contract(
            "target:\n movq %rdi, -8(%rbp)\n leaq 4(%rax), %rdx\n movl (%rdx), %eax\n ret\n"
        )
        self.assertEqual([arg.slot for arg in contract.arguments], ["RDI"])

    def test_rax_write_alone_never_enables_return_comparison(self):
        contract = infer_contract("target:\n movl $7, %eax\n ret\n")
        self.assertEqual(contract.return_spec.kind, "integer_or_void")
        self.assertFalse(contract.return_spec.observable)

    def test_contract_graph_v2_round_trip_is_content_addressed(self):
        legacy = infer_contract("target:\n movl %edi, 8(%rsi)\n ret\n")
        contract = ContractGraphV2.from_static_contract(
            legacy, sample_id="fixture:target:O0"
        )
        restored = ContractGraphV2.from_dict(contract.to_dict())
        self.assertEqual(restored, contract)
        self.assertEqual(restored.content_hash, contract.content_hash)
        self.assertEqual(restored.abi, "x86_64_sysv")
        self.assertEqual(restored.objects[0].read_ranges[0].to_list(), [8, 12])

    def test_contract_graph_v2_rejects_out_of_bounds_ranges(self):
        value = {
            "schema_version": SCHEMA_VERSION,
            "sample_id": "fixture:target:O0",
            "contract_id": "K0",
            "abi": "x86_64_sysv",
            "arguments": [
                {
                    "slot": 0,
                    "register": "RDI",
                    "kind_candidates": ["pointer"],
                    "object_ref": "obj0",
                    "confidence": 0.9,
                    "evidence_ids": ["insn:1"],
                }
            ],
            "objects": [
                {
                    "object_id": "obj0",
                    "argument_slot": "RDI",
                    "min_size": 4,
                    "alignment": 4,
                    "read_ranges": [[0, 8]],
                    "write_ranges": [],
                    "evidence_ids": ["mem:1"],
                }
            ],
            "return": {
                "kind_candidates": ["void"],
                "confidence": 0.7,
                "observable": False,
                "evidence_ids": [],
            },
            "relations": [],
            "globals": [],
            "dependencies": [],
            "unsupported_reasons": [],
            "confidence": 0.8,
            "evidence_ids": [],
        }
        with self.assertRaisesRegex(ContractValidationError, "exceeds min_size"):
            ContractGraphV2.from_dict(value)

    def test_automatic_contract_conversion_is_not_labeled_known_truth(self):
        legacy = infer_contract("target:\n movl %edi, (%rsi)\n ret\n")
        contract = ContractGraphV2.from_static_contract(
            legacy, sample_id="fixture:target:O0"
        )
        runner_contract = contract.to_runner_contract()
        self.assertEqual(runner_contract.source, "automatic_contract_graph_v2")
        self.assertEqual(runner_contract.arguments[1]["kind"], "pointer")

    def test_privacy_gate_catches_aliases_and_nested_answer_fields(self):
        leaked = find_private_metadata_paths(
            {
                "source_type": "fixture",
                "nested": [
                    {"referenceSource": "secret"},
                    {"ground-truth-output": 7},
                    {"testCases": []},
                ],
            }
        )
        self.assertNotIn("metadata.source_type", leaked)
        self.assertEqual(
            leaked,
            [
                "metadata.nested[0].referenceSource",
                "metadata.nested[1].ground-truth-output",
                "metadata.nested[2].testCases",
            ],
        )

    def test_phase2_selection_keeps_complete_groups_and_is_deterministic(self):
        rows = []
        for group in range(4):
            for optimization in ("O0", "O1", "O2", "O3"):
                rows.append(
                    {
                        "sample_id": f"sample:{group}:{optimization}",
                        "source_group_id": f"group:{group}",
                        "optimization": optimization,
                        "binary": {"path": f"objects/{group}-{optimization}.o"},
                        "assembly": {
                            "objdump_att_instruction_only": (
                                "target:\n movl (%rdi), %eax\n ret\n"
                                if group % 2
                                else "target:\n movl %edi, %eax\n ret\n"
                            )
                        },
                    }
                )
        first = build_group_selection_manifest(
            rows,
            dataset_id="fixture",
            split="test",
            group_count=3,
            seed=7,
        )
        second = build_group_selection_manifest(
            reversed(rows),
            dataset_id="fixture",
            split="test",
            group_count=3,
            seed=7,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["sample_count"], 12)
        by_group = {}
        for entry in first["entries"]:
            by_group.setdefault(entry["source_group_id"], set()).add(
                entry["optimization"]
            )
        self.assertEqual(len(by_group), 3)
        self.assertTrue(
            all(values == {"O0", "O1", "O2", "O3"} for values in by_group.values())
        )

    def test_normalized_ir_makes_att_and_intel_operand_order_equivalent(self):
        att = parse_assembly("target:\n movl %edi, 8(%rsi)\n ret\n", syntax="att")
        intel = parse_assembly(
            "target:\n mov DWORD PTR [rsi + 8], edi\n ret\n", syntax="intel"
        )
        self.assertEqual(att[0].operands[0].register, "RDI")
        self.assertEqual(intel[0].operands[0].register, "RDI")
        self.assertEqual(att[0].operands[1].memory.base, "RSI")
        self.assertEqual(intel[0].operands[1].memory.base, "RSI")
        self.assertEqual(att[0].operands[1].memory.displacement, 8)
        self.assertEqual(intel[0].operands[1].memory.displacement, 8)

    def test_taint_tracks_spill_reload_and_derived_pointer(self):
        instructions = parse_assembly(
            """
target:
  movq %rdi, -8(%rbp)
  movq -8(%rbp), %rax
  leaq 8(%rax), %rcx
  movl (%rcx), %edx
  ret
""",
            syntax="att",
        )
        analysis = analyze_taint(instructions)
        self.assertIn("RDI", analysis.argument_evidence)
        access = analysis.pointer_evidence["RDI"][0]
        self.assertEqual(access.via_register, "RCX")
        self.assertEqual(access.direction, "read")
        self.assertEqual(access.width, 4)

    def test_taint_does_not_treat_defined_argument_register_as_input(self):
        analysis = analyze_taint(
            parse_assembly(
                "target:\n movl $0, %edi\n movl %edi, %eax\n ret\n",
                syntax="att",
            )
        )
        self.assertNotIn("RDI", analysis.argument_evidence)
        self.assertIn("rax_defined_before_return", analysis.return_evidence[0])

    def test_taint_records_write_direction_without_calling_lea_a_memory_read(self):
        analysis = analyze_taint(
            parse_assembly(
                "target:\n leaq 4(%rdi), %rax\n movl %esi, (%rax)\n ret\n",
                syntax="att",
            )
        )
        accesses = analysis.pointer_evidence["RDI"]
        self.assertEqual(len(accesses), 1)
        self.assertEqual(accesses[0].direction, "write")

    def test_nop_alignment_operand_is_not_memory_or_pointer_evidence(self):
        analysis = analyze_taint(
            parse_assembly(
                "target:\n movl %esi, %eax\n nopl 0(%rax)\n ret\n",
                syntax="att",
            )
        )
        self.assertNotIn("RSI", analysis.pointer_evidence)

    def test_call_does_not_promote_untouched_abi_registers_to_parameters(self):
        analysis = analyze_taint(
            parse_assembly(
                """
target:
 movl %edi, %eax
 movl %eax, %esi
 leaq .rodata(%rip), %rdi
 call printf
 xorl %eax, %eax
 ret
""",
                syntax="att",
            )
        )
        self.assertIn("RDI", analysis.argument_evidence)
        self.assertNotIn("RDX", analysis.argument_evidence)
        self.assertNotIn("RCX", analysis.argument_evidence)
        self.assertNotIn("R8", analysis.argument_evidence)
        self.assertNotIn("R9", analysis.argument_evidence)

    def test_top_k_contracts_rank_pointer_evidence_first(self):
        analysis = analyze_taint(
            parse_assembly(
                "target:\n movl %edi, 8(%rsi)\n ret\n", syntax="att"
            )
        )
        candidates = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
            max_candidates=4,
        )
        self.assertEqual(len(candidates), 4)
        self.assertEqual(candidates[0].arguments[0].kind_candidates[0], "integer")
        self.assertEqual(candidates[0].arguments[1].kind_candidates[0], "pointer")
        self.assertEqual(candidates[0].objects[0].write_ranges[0].to_list(), [8, 12])
        self.assertEqual(
            [item.confidence for item in candidates],
            sorted((item.confidence for item in candidates), reverse=True),
        )

    def test_return_taint_prioritizes_object_pointer_return(self):
        analysis = analyze_taint(
            parse_assembly(
                "target:\n movl (%rdi), %ecx\n movq %rdi, %rax\n ret\n",
                syntax="att",
            )
        )
        candidates = generate_contract_candidates(
            analysis,
            sample_id="fixture:return-pointer:O2",
            abi="sysv-x86_64",
            max_candidates=4,
        )
        self.assertIn("arg:RDI", analysis.return_taint)
        self.assertEqual(candidates[0].return_spec.kind_candidates[0], "object_pointer")

    def test_symbol_address_return_prioritizes_object_pointer_return(self):
        analysis = analyze_taint(
            parse_assembly(
                "target:\n leaq version_string(%rip), %rax\n ret\n",
                syntax="att",
            )
        )
        candidates = generate_contract_candidates(
            analysis,
            sample_id="fixture:return-global-pointer:O2",
            abi="sysv-x86_64",
            max_candidates=4,
        )
        self.assertIn("symbol:version_string", analysis.return_taint)
        self.assertEqual(candidates[0].return_spec.kind_candidates[0], "object_pointer")

    def test_top_k_contract_supports_phase4_six_slot_abi(self):
        """Phase 4 lifts the V1 three-argument limit; RCX/R8/R9 are now
        supported by the V2 Runner and the static inference layer, so the
        top-K generator must not flag them as unsupported_argument_slots."""

        analysis = analyze_taint(
            parse_assembly("target:\n movl %ecx, %eax\n ret\n", syntax="att")
        )
        contract = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
        )[0]
        self.assertNotIn("unsupported_argument_slots:RCX", contract.unsupported_reasons)

    def test_probe_plan_is_deterministic_repeated_and_budgeted(self):
        analysis = analyze_taint(
            parse_assembly("target:\n movl (%rdi), %eax\n ret\n", syntax="att")
        )
        contract = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
        )[0]
        first = generate_probe_plan(
            contract, base_seed=17, max_executions=10, repetitions=2
        )
        second = generate_probe_plan(
            contract, base_seed=17, max_executions=10, repetitions=2
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 10)
        self.assertEqual(first[0].input_case, first[1].input_case)
        self.assertEqual(first[0].stability_group, first[1].stability_group)
        self.assertNotEqual(first[0].probe_id, first[1].probe_id)
        self.assertTrue(any(not item.expected_safe for item in first))

    def test_probe_budget_is_round_robin_across_pointer_and_integer_slots(self):
        analysis = analyze_taint(
            parse_assembly("target:\n add %rsi, (%rdi)\n ret\n", syntax="att")
        )
        contract = generate_contract_candidates(
            analysis,
            sample_id="fixture:mixed-probes:O2",
            abi="sysv-x86_64",
        )[0]
        probes = generate_probe_plan(
            contract, base_seed=9, max_executions=16, repetitions=2
        )
        self.assertTrue(
            any(
                isinstance(item.input_case.gpr["RSI"], int)
                and item.input_case.gpr["RSI"] != 0
                for item in probes
            )
        )
        self.assertTrue(any(item.purpose.startswith("object_boundary:RDI") for item in probes))

    def test_contract_score_ignores_optional_null_and_constant_residual_rax(self):
        analysis = analyze_taint(
            parse_assembly("target:\n movl (%rdi), %eax\n ret\n", syntax="att")
        )
        contract = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
        )[0]
        probes = generate_probe_plan(
            contract, base_seed=3, max_executions=6, repetitions=2
        )
        observations = []
        for probe in probes:
            if probe.expected_safe:
                observations.append(
                    {
                        "status": "returned",
                        "return": {"valid": True, "kind": "integer", "rax": 0},
                        "objects": {},
                        "globals": {},
                        "elapsed_us": 1 + probe.repetition,
                    }
                )
            else:
                observations.append(
                    {
                        "status": "signal",
                        "signal": "SIGSEGV",
                        "return": {"valid": False},
                        "objects": {},
                        "globals": {},
                        "elapsed_us": 1,
                    }
                )
        score = score_contract(contract, probes, tuple(observations))
        self.assertEqual(score.valid, 1.0)
        self.assertEqual(score.stable, 1.0)
        self.assertEqual(score.effect, 0.0)

    def test_contract_probe_mode_is_explicitly_available(self):
        backend = BinOracleBackend(
            {
                "mode": "contract_probe",
                "strict_privacy": True,
                "max_contract_candidates": 4,
                "probe_executions_per_contract": 8,
                "probe_repetitions": 2,
            }
        )
        self.assertEqual(backend.engine.mode, "contract_probe")
        audited = BinOracleBackend(
            {
                "mode": "contract_audit",
                "strict_privacy": True,
                "audit_min_score_margin": 0.05,
            }
        )
        self.assertEqual(audited.engine.mode, "contract_audit")
        repair = BinOracleBackend(
            {
                "mode": "dynamic_repair",
                "abi": "sysv-x86_64",
                "max_repair_iterations": 3,
            }
        )
        self.assertEqual(repair.engine.mode, "dynamic_repair")
        self.assertEqual(repair.engine.max_repair_iterations, 3)

    def test_contract_auditor_accepts_only_clear_threshold_winner(self):
        analysis = analyze_taint(
            parse_assembly("target:\n movl (%rdi), %eax\n ret\n", syntax="att")
        )
        candidates = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
            max_candidates=2,
        )
        records = [
            {
                "status": "dynamic_scored",
                "contract_id": candidates[0].contract_id,
                "total": 0.95,
                "safe_observation_count": 8,
                "components": {
                    "valid": 1.0,
                    "stable": 1.0,
                    "effect": 1.0,
                    "boundary": 1.0,
                },
            },
            {
                "status": "dynamic_scored",
                "contract_id": candidates[1].contract_id,
                "total": 0.70,
                "safe_observation_count": 8,
                "components": {
                    "valid": 1.0,
                    "stable": 1.0,
                    "effect": 1.0,
                    "boundary": 1.0,
                },
            },
        ]
        decision = audit_contracts(
            candidates, records, thresholds=AuditThresholds()
        )
        self.assertEqual(decision.decision, "accepted")
        self.assertEqual(decision.selected_contract, candidates[0].contract_id)

        records[1]["total"] = 0.93
        ambiguous = audit_contracts(
            candidates, records, thresholds=AuditThresholds()
        )
        self.assertEqual(ambiguous.decision, "ambiguous")
        self.assertIsNone(ambiguous.selected_contract)

    def test_frozen_harness_manifest_is_content_addressed_and_tamper_evident(self):
        analysis = analyze_taint(
            parse_assembly("target:\n movl (%rdi), %eax\n ret\n", syntax="att")
        )
        contract = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
        )[0]
        probes = generate_probe_plan(contract, max_executions=4, repetitions=2)
        manifest = freeze_harness_manifest(
            contract=contract,
            probes=probes,
            observation_policy={"compare_return": True},
            runner_version="runner-test",
            target_function="target",
            probe_seed=0,
            resource_limits={"timeout_ms": 50},
        )
        self.assertTrue(verify_harness_manifest(manifest))
        tampered = dict(manifest)
        tampered["probe_count"] += 1
        self.assertFalse(verify_harness_manifest(tampered))

    def test_candidate_externalization_removes_internal_target_linkage(self):
        source = "static inline int target(int value) { return value + 1; }"
        result = externalize_candidate(source, "target")
        self.assertNotIn("static", result)
        self.assertNotIn("inline", result)
        self.assertIn("int target", result)

    def test_differential_comparison_respects_frozen_observation_policy(self):
        original = {
            "status": "returned",
            "return": {"valid": True, "kind": "integer", "rax": 7},
            "objects": {"obj0": {"after_bytes_hex": "0102"}},
            "globals": {},
        }
        candidate = {
            "status": "returned",
            "return": {"valid": True, "kind": "integer", "rax": 8},
            "objects": {"obj0": {"after_bytes_hex": "0103"}},
            "globals": {},
        }
        ignored_return = compare_observations(
            "probe:0", original, candidate, compare_return=False
        )
        self.assertEqual(ignored_return.kinds, ("memory",))
        compared_return = compare_observations(
            "probe:0", original, candidate, compare_return=True
        )
        self.assertEqual(compared_return.kinds, ("return", "memory"))

    def test_counterexample_minimizer_removes_only_irrelevant_integer(self):
        contract = KnownContract.from_dict(
            {
                "contract_id": "K-min",
                "arguments": [
                    {"slot": "RDI", "kind": "integer"},
                    {"slot": "RSI", "kind": "integer"},
                ],
                "return": {"kind": "integer", "observable": True},
                "objects": [],
                "source": "automatic_contract_graph_v2",
            }
        )
        input_case = InputCase.from_dict(
            {
                "contract_id": "K-min",
                "gpr": {"RDI": 5, "RSI": 9},
                "objects": {},
                "globals": {},
                "seed": 1,
            },
            contract=contract,
        )
        probe = type(
            "Probe",
            (),
            {"probe_id": "p0", "input_case": input_case},
        )()
        result = minimize_counterexample(
            probe,
            contract=contract,
            is_counterexample=lambda value: value.gpr["RDI"] == 5,
        )
        self.assertEqual(result.input_case.gpr, {"RDI": 5, "RSI": 0})
        self.assertEqual([item.kept for item in result.attempts], [False, True])

    def test_evidence_package_is_content_identified_and_marks_no_harness_mutation(self):
        analysis = analyze_taint(
            parse_assembly("target:\n movl (%rdi), %eax\n ret\n", syntax="att")
        )
        contract = generate_contract_candidates(
            analysis,
            sample_id="fixture:target:O0",
            abi="sysv-x86_64",
        )[0]
        probe = generate_probe_plan(contract, max_executions=2, repetitions=2)[0]
        difference = {
            "equivalent": False,
            "kinds": ["return"],
            "details": {"return": {}},
        }
        package = build_evidence_package(
            sample_id=contract.sample_id,
            contract_hash=contract.content_hash,
            harness_hash="harness-hash",
            probe=probe,
            original={"status": "returned"},
            candidate={"status": "returned"},
            difference=difference,
        )
        self.assertEqual(len(package["evidence_id"]), 64)
        self.assertFalse(package["harness_mutated"])
        self.assertEqual(package["localization"]["status"], "not_implemented")

    def test_inputcase_protocol_accepts_object_and_null_pointer(self):
        contract = KnownContract.from_dict(
            {
                "contract_id": "K-pointer",
                "arguments": [
                    {"slot": "RDI", "kind": "pointer", "object_ref": "obj0"}
                ],
                "return": {"kind": "void", "observable": False},
                "objects": [{"object_id": "obj0", "min_size": 4}],
            }
        )
        object_case = InputCase.from_dict(
            {
                "schema_version": 1,
                "contract_id": "K-pointer",
                "gpr": {"RDI": {"object_ref": "obj0"}},
                "objects": {
                    "obj0": {"size": 4, "bytes_hex": "00010203", "placement": "right"}
                },
                "globals": {},
                "seed": 7,
            },
            contract=contract,
        )
        null_case = InputCase.from_dict(
            {
                "schema_version": 1,
                "contract_id": "K-pointer",
                "gpr": {"RDI": {"null": True}},
                "objects": {},
                "globals": {},
                "seed": 8,
            },
            contract=contract,
        )
        self.assertEqual(object_case.objects["obj0"]["bytes_hex"], "00010203")
        self.assertTrue(null_case.gpr["RDI"]["null"])

    def test_void_observation_ignores_raw_rax_and_tracks_changed_ranges(self):
        contract = KnownContract.from_dict(
            {
                "contract_id": "K-void",
                "arguments": [
                    {"slot": "RDI", "kind": "pointer", "object_ref": "obj0"}
                ],
                "return": {"kind": "void", "observable": False},
                "objects": [{"object_id": "obj0", "min_size": 4}],
            }
        )
        case = InputCase.from_dict(
            {
                "contract_id": "K-void",
                "gpr": {"RDI": {"object_ref": "obj0"}},
                "objects": {"obj0": {"size": 4, "bytes_hex": "00000000"}},
                "globals": {},
                "seed": 1,
            },
            contract=contract,
        )
        observation = normalize_observation(
            {
                "status": "returned",
                "signal": None,
                "return": {"rax": 123456},
                "objects": {
                    "obj0": {"before_hex": "00000000", "after_hex": "002a2a00"}
                },
                "globals": {},
                "elapsed_us": 3,
            },
            contract=contract,
            input_case=case,
        )
        self.assertFalse(observation["return"]["valid"])
        self.assertNotIn("rax", observation["return"])
        self.assertEqual(observation["objects"]["obj0"]["changed_ranges"], [[1, 3]])

    def test_dependencies_distinguish_whitelisted_and_unknown_direct_calls(self):
        dependencies = classify_dependencies(
            ["memcpy", "printf", "project_helper"],
            [
                {"symbol": "memcpy"},
                {"symbol": "printf"},
                {"symbol": "project_helper"},
            ],
        )
        by_name = {item["name"]: item for item in dependencies}
        self.assertTrue(by_name["memcpy"]["supported"])
        self.assertTrue(by_name["printf"]["supported"])
        self.assertFalse(by_name["project_helper"]["supported"])
        self.assertTrue(by_name["project_helper"]["direct_from_target"])

    def test_common_symbols_are_globals_not_undefined_dependencies(self):
        from plugins.binoracle.symbol_table import collect_global_objects

        symbols = [
            {
                "name": "counter",
                "type": "OBJECT",
                "binding": "GLOBAL",
                "section": "COMMON",
                "size": 4,
                "undefined": False,
            }
        ]
        globals_ = collect_global_objects(symbols)
        self.assertEqual(globals_[0]["name"], "counter")

    def test_metric_reads_backend_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "binoracle_metadata.json").write_text(
                json.dumps({"executions": 7}), encoding="utf-8"
            )
            context = type("Context", (), {"artifact_dir": str(root)})()
            metric = ExecutionCountMetric()
            self.assertEqual(metric.evaluate(None, None, context=context), 7.0)
            self.assertEqual(metric.aggregate([7.0, 3.0, None])["mean"], 5.0)
            compile_metric = CandidateCompileMetric()
            self.assertEqual(compile_metric.evaluate(None, None, context=context), 0.0)
            (root / "binoracle_metadata.json").write_text(
                json.dumps({"candidate_compile": True}), encoding="utf-8"
            )
            self.assertEqual(
                compile_metric.evaluate(None, None, context=context), 1.0
            )

    def test_exebench_adapter_can_hide_signature_metadata(self):
        row = {
            "sample_id": "eb:test:O0",
            "source_group_id": "eb:test",
            "function_name": "target",
            "optimization": "O0",
            "source_type": "fixture",
            "source_metadata": {"language": "c"},
            "source": {
                "code": "void target(int *out){*out=1;}",
                "signature": ["void", "int *"],
            },
            "assembly": {"objdump_att_instruction_only": "target:\n ret\n"},
            "evaluation": {},
        }
        with tempfile.TemporaryDirectory() as temporary:
            dataset = Path(temporary) / "dataset.json"
            dataset.write_text(json.dumps({"samples": [row]}), encoding="utf-8")
            adapter = ExeBenchFlatAdapter(
                {
                    "id": "eb",
                    "path": str(dataset),
                    "assembly_view": "objdump_att_instruction_only",
                    "expose_signature_metadata": False,
                },
                base_dir=PROJECT,
            )
            sample = list(adapter.iter_samples())[0]
        self.assertNotIn("signature", sample.metadata)

    def test_framework_runner_executes_binoracle_as_python_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "answer.o"
            _minimal_elf64_rel(binary, "answer")
            config = {
                "_config_hash": "binoracle-runner",
                "_config_path": str(PROJECT / "fixture.yaml"),
                "workspace_root": str(PROJECT),
                "datasets": [
                    {
                        "id": "binoracle-fixture",
                        "type": "tests.test_binoracle_backend:BinOracleFixtureDataset",
                        "path": ".",
                        "binary_path": str(binary),
                    }
                ],
                "decompilers": [
                    {
                        "id": "binoracle",
                        "type": "python",
                        "plugin": "plugins.binoracle_backend:BinOracleBackend",
                        "required_inputs": ["binary", "assembly", "pseudocode"],
                        "plugin_config": {
                            "mode": "static_passthrough",
                            "strict_privacy": True,
                            "require_relocatable": True,
                        },
                    }
                ],
                "metrics": [
                    "behavioral_pass",
                    {"type": "plugins.binoracle_metrics:ExecutionCountMetric"},
                ],
                "postprocessors": [],
                "executor": {
                    "type": "local",
                    "require_linux": False,
                    "memory_mb": 512,
                    "max_file_mb": 16,
                },
                "preflight": {"mode": "strict"},
                "output": {"root": str(root / "runs"), "cache": str(root / "cache")},
            }
            run_dir = root / "run"
            summary = EvaluationRunner(config, run_dir=run_dir).run()
            result = json.loads((run_dir / "results.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(summary["overall"][0]["behavioral_pass_rate"], 1.0)
        self.assertTrue(result["behavioral_pass"])
        self.assertEqual(result["metrics"]["binoracle_executions"], 0.0)


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
    "BinOracle ABI runner integration requires Linux x86-64",
)
class BinOracleRunnerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("gcc") is None:
            raise unittest.SkipTest("gcc is required")
        try:
            import elftools  # noqa: F401
        except ImportError as error:
            raise unittest.SkipTest("pyelftools is required") from error
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.object = cls.root / "binoracle_v1_functions.o"
        source = PROJECT / "tests" / "fixtures" / "binoracle_v1_functions.c"
        completed = subprocess.run(
            ["gcc", "-O0", "-fno-pie", "-c", str(source), "-o", str(cls.object)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def _run(self, function_name, contract, inputs, pseudocode="void placeholder(void) {}"):
        request = DecompileRequest(
            dataset_id="binoracle-runtime-fixture",
            split="test",
            sample_id=f"fixture:{function_name}:O0",
            source_group_id=f"fixture:{function_name}",
            function_name=function_name,
            language="c",
            optimization="O0",
            assembly=AssemblyInput(f"{function_name}:\n ret\n", "AT&T", "fixture"),
            metadata={"source_type": "fixture"},
            binary=BinaryInput(
                path=str(self.object), format="ELF-REL", architecture="x86_64"
            ),
            pseudocode=PseudocodeInput(pseudocode, "fixture", "fixture"),
        )
        artifact = self.root / function_name
        backend = BinOracleBackend(
            {
                "mode": "dynamic_audit",
                "strict_privacy": True,
                "require_relocatable": True,
                "known_contract": contract,
                "input_cases": inputs,
                "runner_execution_timeout_ms": 50,
            }
        )
        backend.prepare([request])
        result = backend.decompile(request, artifact)
        self.assertTrue(result.success, result.log)
        observations = [
            json.loads(line)
            for line in (artifact / "binoracle" / "original_observations.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        return observations, artifact

    def test_automatic_contract_probe_scores_without_freezing_harness(self):
        function_name = "set_value"
        request = DecompileRequest(
            dataset_id="binoracle-runtime-fixture",
            split="test",
            sample_id=f"fixture:{function_name}:O0",
            source_group_id=f"fixture:{function_name}",
            function_name=function_name,
            language="c",
            optimization="O0",
            assembly=AssemblyInput(
                "set_value:\n movl $42, (%rdi)\n ret\n", "AT&T", "fixture"
            ),
            metadata={"source_type": "fixture"},
            binary=BinaryInput(
                path=str(self.object), format="ELF-REL", architecture="x86_64"
            ),
            pseudocode=PseudocodeInput(
                "void set_value(int *output) { *output = 42; }",
                "fixture",
                "fixture",
            ),
        )
        artifact = self.root / "automatic-contract-probe"
        backend = BinOracleBackend(
            {
                "mode": "contract_probe",
                "strict_privacy": True,
                "require_relocatable": True,
                "max_contract_candidates": 2,
                "probe_executions_per_contract": 8,
                "probe_repetitions": 2,
                "runner_execution_timeout_ms": 50,
            }
        )
        backend.prepare([request])
        result = backend.decompile(request, artifact)
        self.assertTrue(result.success, result.log)
        metadata = json.loads(
            (artifact / "binoracle_metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            metadata["contract_selection_status"], "dynamic_scored_unreviewed"
        )
        self.assertFalse(metadata["harness_frozen"])
        self.assertGreater(metadata["valid_original_executions"], 0)
        self.assertFalse((artifact / "binoracle" / "harness_manifest.json").exists())

    def test_automatic_contract_audit_freezes_clear_winner(self):
        function_name = "set_value"
        request = DecompileRequest(
            dataset_id="binoracle-runtime-fixture",
            split="test",
            sample_id=f"fixture:{function_name}:audit:O0",
            source_group_id=f"fixture:{function_name}:audit",
            function_name=function_name,
            language="c",
            optimization="O0",
            assembly=AssemblyInput(
                "set_value:\n movl $42, (%rdi)\n ret\n", "AT&T", "fixture"
            ),
            metadata={"source_type": "fixture"},
            binary=BinaryInput(
                path=str(self.object), format="ELF-REL", architecture="x86_64"
            ),
            pseudocode=PseudocodeInput(
                "void set_value(int *output) { *output = 42; }",
                "fixture",
                "fixture",
            ),
        )
        artifact = self.root / "automatic-contract-audit"
        backend = BinOracleBackend(
            {
                "mode": "contract_audit",
                "strict_privacy": True,
                "require_relocatable": True,
                "max_contract_candidates": 2,
                "probe_executions_per_contract": 8,
                "probe_repetitions": 2,
                "runner_execution_timeout_ms": 50,
            }
        )
        backend.prepare([request])
        result = backend.decompile(request, artifact)
        self.assertTrue(result.success, result.log)
        metadata = json.loads(
            (artifact / "binoracle_metadata.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            metadata["contract_selection_status"],
            ("audit_accepted_frozen", "audit_accepted_holdout_frozen"),
        )
        self.assertTrue(metadata["harness_frozen"])
        manifest = json.loads(
            (artifact / "binoracle" / "harness_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(verify_harness_manifest(manifest))

    def test_frozen_harness_differential_detects_candidate_memory_error(self):
        function_name = "set_value"
        request = DecompileRequest(
            dataset_id="binoracle-runtime-fixture",
            split="test",
            sample_id=f"fixture:{function_name}:differential:O0",
            source_group_id=f"fixture:{function_name}:differential",
            function_name=function_name,
            language="c",
            optimization="O0",
            assembly=AssemblyInput(
                "set_value:\n movl $42, (%rdi)\n ret\n", "AT&T", "fixture"
            ),
            metadata={"source_type": "fixture"},
            binary=BinaryInput(
                path=str(self.object), format="ELF-REL", architecture="x86_64"
            ),
            pseudocode=PseudocodeInput(
                "void set_value(int *output) { *output = 41; }",
                "fixture",
                "fixture",
            ),
        )
        artifact = self.root / "frozen-differential"
        backend = BinOracleBackend(
            {
                "mode": "differential",
                "strict_privacy": True,
                "require_relocatable": True,
                "max_contract_candidates": 2,
                "probe_executions_per_contract": 8,
                "probe_repetitions": 2,
                "runner_execution_timeout_ms": 50,
            }
        )
        backend.prepare([request])
        result = backend.decompile(request, artifact)
        self.assertTrue(result.success, result.log)
        summary = json.loads(
            (artifact / "binoracle" / "differential_summary.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(summary["candidate_compile"])
        self.assertTrue(summary["candidate_link"])
        self.assertFalse(summary["differential_pass"])
        self.assertGreater(summary["difference_kinds"]["memory"], 0)
        self.assertGreater(summary["evidence_packages"], 0)
        packages = [
            json.loads(line)
            for line in (artifact / "binoracle" / "evidence_packages.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertTrue(all(not item["harness_mutated"] for item in packages))

    def test_integer_return_and_three_gpr_arguments(self):
        observations, _ = self._run(
            "sum_three",
            {
                "contract_id": "K-sum3",
                "arguments": [
                    {"slot": "RDI", "kind": "integer"},
                    {"slot": "RSI", "kind": "integer"},
                    {"slot": "RDX", "kind": "integer"},
                ],
                "return": {"kind": "integer", "observable": True},
                "objects": [],
            },
            [
                {
                    "contract_id": "K-sum3",
                    "gpr": {"RDI": 2, "RSI": 3, "RDX": 4},
                    "objects": {},
                    "globals": {},
                    "seed": 11,
                }
            ],
            "int sum_three(int a, int b, int c) { return a + b + c; }",
        )
        self.assertEqual(observations[0]["return"]["rax"], 9)

    def test_void_pointer_memory_and_global_observation(self):
        observations, artifact = self._run(
            "set_value",
            {
                "contract_id": "K-set",
                "arguments": [
                    {"slot": "RDI", "kind": "pointer", "object_ref": "obj0"}
                ],
                "return": {"kind": "void", "observable": False},
                "objects": [{"object_id": "obj0", "min_size": 4}],
            },
            [
                {
                    "contract_id": "K-set",
                    "gpr": {"RDI": {"object_ref": "obj0"}},
                    "objects": {"obj0": {"size": 4, "bytes_hex": "00000000"}},
                    "globals": {},
                    "seed": 12,
                }
            ],
            "void set_value(int *output) { *output = 42; }",
        )
        self.assertFalse(observations[0]["return"]["valid"])
        self.assertEqual(observations[0]["objects"]["obj0"]["after_bytes_hex"], "2a000000")
        self.assertEqual(observations[0]["objects"]["obj0"]["changed_ranges"], [[0, 1]])
        self.assertTrue((artifact / "binoracle" / "runner_build.json").is_file())

        global_observations, _ = self._run(
            "update_global",
            {
                "contract_id": "K-global",
                "arguments": [],
                "return": {"kind": "void", "observable": False},
                "objects": [],
            },
            [
                {
                    "contract_id": "K-global",
                    "gpr": {},
                    "objects": {},
                    "globals": {},
                    "seed": 13,
                }
            ],
        )
        self.assertEqual(
            global_observations[0]["globals"]["binoracle_counter"]["after_bytes_hex"],
            "07000000",
        )

    def test_null_pointer_crash_timeout_and_guard_directions(self):
        null_observations, _ = self._run(
            "null_safe",
            {
                "contract_id": "K-null",
                "arguments": [
                    {"slot": "RDI", "kind": "pointer", "object_ref": "obj0"}
                ],
                "return": {"kind": "integer", "observable": True},
                "objects": [{"object_id": "obj0", "min_size": 4}],
            },
            [
                {
                    "contract_id": "K-null",
                    "gpr": {"RDI": {"null": True}},
                    "objects": {},
                    "globals": {},
                    "seed": 14,
                }
            ],
        )
        self.assertEqual(null_observations[0]["return"]["rax"], 17)

        for function_name, expected_status in (("crash_now", "signal"), ("loop_forever", "timeout")):
            observations, _ = self._run(
                function_name,
                {
                    "contract_id": f"K-{function_name}",
                    "arguments": [],
                    "return": {"kind": "void", "observable": False},
                    "objects": [],
                },
                [
                    {
                        "contract_id": f"K-{function_name}",
                        "gpr": {},
                        "objects": {},
                        "globals": {},
                        "seed": 15,
                    }
                ],
            )
            self.assertEqual(observations[0]["status"], expected_status)

        for function_name, placement, fault_class, offset in (
            ("write_right", "right", "obj0_right_guard", 4),
            ("write_left", "left", "obj0_left_guard", -1),
        ):
            observations, _ = self._run(
                function_name,
                {
                    "contract_id": f"K-{function_name}",
                    "arguments": [
                        {"slot": "RDI", "kind": "pointer", "object_ref": "obj0"}
                    ],
                    "return": {"kind": "void", "observable": False},
                    "objects": [{"object_id": "obj0", "min_size": 4}],
                },
                [
                    {
                        "contract_id": f"K-{function_name}",
                        "gpr": {"RDI": {"object_ref": "obj0"}},
                        "objects": {
                            "obj0": {
                                "size": 4,
                                "bytes_hex": "00000000",
                                "placement": placement,
                            }
                        },
                        "globals": {},
                        "seed": 16,
                    }
                ],
            )
            self.assertEqual(observations[0]["fault_address_class"], fault_class)
            self.assertEqual(observations[0]["relative_offset"], offset)


if __name__ == "__main__":
    unittest.main()
