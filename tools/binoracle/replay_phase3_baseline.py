from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.binoracle.phase3 import replay_phase3_baseline  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay every frozen Phase 3 Harness.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execution-timeout-ms", type=int, default=100)
    parser.add_argument("--allow-mismatch", action="store_true")
    args = parser.parse_args()
    report = replay_phase3_baseline(
        args.manifest,
        output_path=args.output,
        runner_config={"runner_execution_timeout_ms": args.execution_timeout_ms},
    )
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "harnesses_total",
                    "harnesses_replay_match",
                    "harnesses_replay_mismatch",
                    "replay_match_rate",
                    "executions",
                    "diagnostic_timing_changes",
                    "content_hash",
                )
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if args.allow_mismatch or not report["harnesses_replay_mismatch"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
