from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.binoracle.selection import build_group_selection_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a deterministic BinOracle Phase 2 O0-O3 group selection manifest."
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset-id", default="exebench-binoracle")
    parser.add_argument("--split", default="benchmark")
    parser.add_argument("--groups", type=int, required=True)
    parser.add_argument("--seed", type=int, default=20260720)
    parser.add_argument("--assembly-view", default="objdump_att_instruction_only")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        parser.error(f"output already exists: {args.output}; pass --force to replace it")
    payload = json.loads(args.dataset.read_text(encoding="utf-8"))
    rows = payload.get("samples")
    if not isinstance(rows, list):
        parser.error("dataset must contain a top-level samples array")
    manifest = build_group_selection_manifest(
        rows,
        dataset_id=args.dataset_id,
        split=args.split,
        group_count=args.groups,
        seed=args.seed,
        assembly_view=args.assembly_view,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "selection_hash": manifest["selection_hash"],
                "sample_count": manifest["sample_count"],
                "group_count": manifest["binoracle_selection"]["group_count"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
