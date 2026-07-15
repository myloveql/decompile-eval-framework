from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .metrics import create_metrics
from .plugins import plugin_inventory
from .reporting import write_report
from .runner import EvaluationRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="decomp-eval", description="Extensible decompiler evaluation framework")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-config", "validate-dataset", "run"):
        child = sub.add_parser(name)
        child.add_argument("--config", type=Path, required=True)
        if name in {"validate-dataset", "run"}:
            child.add_argument("--run-dir", type=Path)
        if name == "validate-dataset":
            child.add_argument("--force", action="store_true")
        if name == "run":
            child.add_argument("--resume", action="store_true")
    report = sub.add_parser("report")
    report.add_argument("--run-dir", type=Path, required=True)
    sub.add_parser("list-plugins")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-plugins":
            print(json.dumps(plugin_inventory(), ensure_ascii=False, indent=2))
            return 0
        if args.command == "report":
            run_dir = args.run_dir.resolve()
            manifest_path = run_dir / "manifest.json"
            metrics = None
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                metrics = create_metrics(manifest.get("config", {}).get("metrics", []))
            print(json.dumps(write_report(run_dir, metrics), ensure_ascii=False, indent=2))
            return 0
        config = load_config(args.config.resolve())
        if args.command == "validate-config":
            print(json.dumps({"valid": True, "config_hash": config["_config_hash"]}, indent=2))
            return 0
        runner = EvaluationRunner(config, run_dir=args.run_dir, resume=getattr(args, "resume", False))
        if args.command == "validate-dataset":
            result = runner.validate_datasets(force=args.force)
        else:
            result = runner.run()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
