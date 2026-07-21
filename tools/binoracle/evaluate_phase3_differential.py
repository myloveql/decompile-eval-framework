from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.binoracle.phase3_reporting import (  # noqa: E402
    summarize_phase3_differential,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize a fixed-denominator Phase 3 differential run.")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    report = summarize_phase3_differential(args.run_dir, output_dir=args.output_dir)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
