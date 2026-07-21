from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from plugins.binoracle.reporting import summarize_phase2_run


class BinOraclePhase2ReportingTests(unittest.TestCase):
    def test_offline_report_keeps_truth_outside_recovery_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "run" / "artifacts" / "dataset" / "backend" / "sample"
            stage = artifact / "binoracle"
            stage.mkdir(parents=True)
            (artifact / "binoracle_public_request.json").write_text(
                json.dumps(
                    {
                        "sample_id": "sample:O0",
                        "source_group_id": "group",
                        "function_name": "target",
                        "optimization": "O0",
                    }
                ),
                encoding="utf-8",
            )
            (artifact / "binoracle_metadata.json").write_text(
                json.dumps(
                    {
                        "contract_selection_status": "audit_rejected",
                        "executions": 4,
                        "runnable_contracts": 1,
                        "leading_contract": "K_static_0",
                    }
                ),
                encoding="utf-8",
            )
            (stage / "contract_candidates.json").write_text(
                json.dumps(
                    [
                        {
                            "contract_id": "K_static_0",
                            "arguments": [
                                {
                                    "register": "RDI",
                                    "kind_candidates": ["pointer", "integer"],
                                    "evidence_ids": ["insn:1"],
                                }
                            ],
                            "return": {"kind_candidates": ["void"]},
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (stage / "contract_scores.json").write_text("[]", encoding="utf-8")
            (stage / "taint_analysis.json").write_text(
                json.dumps({"pointer_evidence": {"RDI": [{"instruction_id": "insn:1"}]}}),
                encoding="utf-8",
            )
            dataset = root / "private.json"
            dataset.write_text(
                json.dumps(
                    {
                        "samples": [
                            {
                                "sample_id": "sample:O0",
                                "source": {"signature": ["void", "int *"]},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = summarize_phase2_run(root / "run", dataset_path=dataset)

            self.assertEqual(report["evaluation_scope"], "offline_private_truth")
            self.assertFalse(report["truth_feedback_to_contract_recovery"])
            self.assertEqual(report["overall"]["complete_contract_top1_rate"], 1.0)
            self.assertEqual(report["overall"]["static_argument_top1_rate"], 1.0)
            self.assertEqual(report["overall"]["dynamic_argument_top1_rate"], 1.0)
            self.assertEqual(report["overall"]["dynamic_return_only_mismatches"], 0)
            self.assertEqual(report["overall"]["random_legal_expected_top1_rate"], 1.0)
            self.assertEqual(report["method_comparison"]["static_top1"], 1.0)
            self.assertTrue(
                (root / "run" / "binoracle_phase2" / "contract_results.jsonl").is_file()
            )
            public_value = json.loads(
                (artifact / "binoracle_public_request.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("signature", public_value)

    def test_report_separates_argument_accuracy_from_return_ambiguity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "run" / "artifacts" / "dataset" / "backend" / "sample"
            stage = artifact / "binoracle"
            stage.mkdir(parents=True)
            (artifact / "binoracle_public_request.json").write_text(
                json.dumps({"sample_id": "sample:O2", "optimization": "O2"}),
                encoding="utf-8",
            )
            (artifact / "binoracle_metadata.json").write_text(
                json.dumps(
                    {
                        "contract_selection_status": "audit_ambiguous",
                        "leading_contract": "integer_return",
                    }
                ),
                encoding="utf-8",
            )
            candidates = [
                {
                    "contract_id": "integer_return",
                    "arguments": [],
                    "return": {"kind_candidates": ["integer"]},
                },
                {
                    "contract_id": "void_return",
                    "arguments": [],
                    "return": {"kind_candidates": ["void"]},
                },
            ]
            (stage / "contract_candidates.json").write_text(
                json.dumps(candidates), encoding="utf-8"
            )
            (stage / "contract_scores.json").write_text("[]", encoding="utf-8")
            (stage / "taint_analysis.json").write_text("{}", encoding="utf-8")
            dataset = root / "private.json"
            dataset.write_text(
                json.dumps(
                    {
                        "samples": [
                            {
                                "sample_id": "sample:O2",
                                "source": {"signature": ["void"]},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = summarize_phase2_run(root / "run", dataset_path=dataset)

            self.assertEqual(report["overall"]["dynamic_leading_top1_rate"], 0.0)
            self.assertEqual(report["overall"]["dynamic_argument_top1_rate"], 1.0)
            self.assertEqual(report["overall"]["dynamic_return_only_mismatches"], 1)
            self.assertEqual(
                report["overall"]["dynamic_return_ambiguous_with_truth"], 1
            )
            self.assertEqual(
                report["overall"]["random_legal_expected_top1_rate"], 0.5
            )


if __name__ == "__main__":
    unittest.main()
