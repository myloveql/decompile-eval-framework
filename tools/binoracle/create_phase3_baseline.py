from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.binoracle.phase3 import create_phase3_baseline  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and verify a Phase 3 frozen-Harness baseline.")
    parser.add_argument("--run-dir", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-invalid", action="store_true")
    args = parser.parse_args()
    manifest = create_phase3_baseline(args.run_dir, output_path=args.output)
    print(json.dumps({key: manifest[key] for key in (
        "frozen_harnesses", "valid_frozen_harnesses", "invalid_frozen_harnesses", "content_hash"
    )}, ensure_ascii=False, indent=2))
    return 0 if args.allow_invalid or not manifest["invalid_frozen_harnesses"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
