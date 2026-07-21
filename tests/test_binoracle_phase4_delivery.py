from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from plugins.binoracle.phase4_delivery import build_delivery_manifest


def _write_sample(artifact_root: Path, *, sample_id: str, group: str, opt: str, frozen: bool, status: str = "frozen", stop_reason: str | None = None, executions: int = 4) -> Path:
    """Drop a minimal sample layout the Phase 4 delivery walker understands."""

    artifact_dir = artifact_root / group / opt
    stage = artifact_dir / "binoracle"
    stage.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "binoracle_public_request.json").write_text(
        json.dumps({"sample_id": sample_id, "source_group_id": group, "optimization": opt}),
        encoding="utf-8",
    )
    (artifact_dir / "binoracle_metadata.json").write_text(
        json.dumps(
            {
                "sample_id": sample_id,
                "source_group_id": group,
                "optimization": opt,
                "harness_frozen": frozen,
                "executions": executions,
                "stop_reason": stop_reason or ("harness_frozen" if frozen else "active_probe_budget_exhausted"),
                "elapsed_seconds": 0.5,
            }
        ),
        encoding="utf-8",
    )
    (stage / "harness_resolution.json").write_text(
        json.dumps(
            {
                "schema_version": "binoracle.harness-resolution.v1",
                "sample_id": sample_id,
                "status": status,
                "terminal": True,
                "reasons": [] if frozen else ["effect_below_threshold"],
                "contract_ids": [sample_id + ":K"],
                "evidence_ids": [],
                "next_action": None,
                "budget": {
                    "max_rounds": 3, "max_executions": 32, "max_wall_seconds": 120.0,
                    "rounds_used": 1, "executions_used": executions,
                    "wall_seconds_used": 0.5, "exhausted": False,
                },
                "round_index": 1,
            }
        ),
        encoding="utf-8",
    )
    return artifact_dir


class Phase4DeliveryTests(unittest.TestCase):
    def test_delivery_manifest_contains_state_matrix_cost_and_failure_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            artifacts = run_dir / "artifacts" / "dataset" / "backend"
            _write_sample(artifacts, sample_id="s1", group="g1", opt="O0", frozen=True)
            _write_sample(artifacts, sample_id="s2", group="g1", opt="O1", frozen=False, status="unverified", stop_reason="active_probe_budget_exhausted")
            _write_sample(artifacts, sample_id="s3", group="g2", opt="O0", frozen=True)
            commitment = {"engine_version": "binoracle-engine-v4-phase4"}
            selection = {"schema": "binoracle.phase4-selection/v1", "sample_count": 3}
            manifest = build_delivery_manifest(
                run_dir, experiment="unit-test", algorithm_commitment=commitment, selection_manifest=selection,
            )
            self.assertEqual(manifest["schema_version"], "binoracle.phase4-delivery.v1")
            self.assertEqual(manifest["experiment"], "unit-test")
            self.assertEqual(manifest["sample_count"], 3)
            self.assertEqual(manifest["algorithm_commitment"], commitment)
            self.assertGreater(len(manifest["artifact_inventory"]), 0)
            # Every artifact entry carries a sha256 hex digest.
            for entry in manifest["artifact_inventory"]:
                self.assertEqual(len(entry["sha256"]), 64)
                self.assertGreater(entry["size_bytes"], 0)

            reports = run_dir / "reports"
            self.assertTrue((reports / "state_transition_matrix.csv").is_file())
            self.assertTrue((reports / "stratified_metrics.json").is_file())
            self.assertTrue((reports / "group_level_coverage.csv").is_file())
            self.assertTrue((reports / "cost_report.json").is_file())
            self.assertTrue((reports / "failure_catalog.md").is_file())
            self.assertTrue((reports / "phase4_sample_records.jsonl").is_file())
            self.assertTrue((run_dir / "delivery_manifest.json").is_file())

            # The fixed-denominator rate is over the full selection.
            stratified = json.loads((reports / "stratified_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(stratified["overall"]["total"], 3)
            self.assertEqual(stratified["overall"]["frozen_harnesses"], 2)
            self.assertAlmostEqual(
                stratified["overall"]["harness_freeze_rate_fixed_denominator"], 2 / 3
            )
            ci = stratified["overall"]["harness_freeze_rate_fixed_denominator_ci95"]
            self.assertEqual(len(ci), 2)
            self.assertLessEqual(ci[0], ci[1])

            # Failures (non-frozen) must be retained in the catalog.
            catalog = (reports / "failure_catalog.md").read_text(encoding="utf-8")
            self.assertIn("s2", catalog)
            self.assertNotIn("s1", catalog)

            cost = json.loads((reports / "cost_report.json").read_text(encoding="utf-8"))
            self.assertEqual(cost["schema_version"], "binoracle.phase4-cost.v1")
            self.assertGreater(cost["executions_total"], 0)

    def test_delivery_manifest_is_deterministic(self) -> None:
        commitment = {"engine_version": "binoracle-engine-v4-phase4"}
        selection = {"schema": "binoracle.phase4-selection/v1", "sample_count": 1}
        with tempfile.TemporaryDirectory() as temporary:
            run_one = Path(temporary) / "one"
            artifacts = run_one / "artifacts" / "dataset" / "backend"
            _write_sample(artifacts, sample_id="x1", group="g", opt="O0", frozen=True)
            first = build_delivery_manifest(run_one, experiment="det", algorithm_commitment=commitment, selection_manifest=selection)
            second = build_delivery_manifest(run_one, experiment="det", algorithm_commitment=commitment, selection_manifest=selection)
            self.assertEqual(first["content_hash"], second["content_hash"])


if __name__ == "__main__":
    unittest.main()
