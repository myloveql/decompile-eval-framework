from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.binoracle.reporting import summarize_phase2_run  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build BinOracle Phase 2 fixed-denominator contract reports."
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Optional private-truth dataset. It is used only by this offline evaluator.",
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    report = summarize_phase2_run(
        args.run_dir,
        dataset_path=args.dataset,
        output_dir=args.output_dir,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
