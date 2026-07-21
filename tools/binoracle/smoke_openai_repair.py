from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from plugins.binoracle.repair import (  # noqa: E402
    OpenAIRepairer,
    RepairBudget,
    RepairRequest,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one bounded OpenAI Responses API repair protocol smoke call."
    )
    parser.add_argument("--model", default="gpt-5.6-terra")
    args = parser.parse_args()
    request = RepairRequest(
        sample_id="binoracle:openai-protocol-smoke:O0",
        candidate_source="long target(long x) { return x; }",
        compile_diagnostics="",
        frozen_harness_hash="a" * 64,
        evidence_packages=(
            {
                "schema_version": "binoracle.evidence.v1",
                "evidence_id": "smoke-return-delta",
                "difference": {"kinds": ["return"]},
                "original_observation": {"status": "returned", "return_value": 2},
                "candidate_observation": {"status": "returned", "return_value": 1},
                "input": {"arguments": [1]},
            },
        ),
        allowed_edit_scope=("target_function",),
        iteration=0,
        remaining_budget=RepairBudget(1, 1, 1, 512),
    )
    repairer = OpenAIRepairer(
        model=args.model,
        max_output_tokens=512,
        reasoning_effort="low",
    )
    response = repairer.repair(request, binary_facts={})
    print(
        json.dumps(
            {"response": response.to_dict(), "audit": repairer.pop_audit_metadata()},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if not response.rationale_codes[0].startswith("model_error:") else 1


if __name__ == "__main__":
    raise SystemExit(main())
