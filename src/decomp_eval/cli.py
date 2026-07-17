from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import load_config
from .metrics import create_metrics
from .plugins import create_dataset, plugin_inventory
from .reporting import write_report
from .runner import EvaluationRunner
from .history import derive_subset, import_run
from .selection import build_selection_manifest
from .util import resolve_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="decomp-eval", description="Extensible decompiler evaluation framework")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-config", "validate-dataset", "run", "generate", "evaluate"):
        child = sub.add_parser(name)
        child.add_argument("--config", type=Path, required=True)
        if name in {"validate-dataset", "run", "generate", "evaluate"}:
            child.add_argument("--run-dir", type=Path)
        if name == "validate-dataset":
            child.add_argument("--force", action="store_true")
        if name in {"run", "generate", "evaluate"}:
            child.add_argument("--resume", action="store_true")
    report = sub.add_parser("report")
    report.add_argument("--run-dir", type=Path, required=True)
    sub.add_parser("list-plugins")
    selection = sub.add_parser(
        "create-selection-manifest",
        help="freeze the samples selected by a config into a reproducible manifest",
    )
    selection.add_argument("--config", type=Path, required=True)
    selection.add_argument("--output", type=Path, required=True)
    selection.add_argument("--force", action="store_true")
    import_parser = sub.add_parser("import-run", help="import historical generations and candidates")
    import_parser.add_argument("--run-dir", type=Path, required=True)
    import_parser.add_argument(
        "--cache-dir", type=Path,
        help="layered cache root; defaults to output.cache from --config",
    )
    import_parser.add_argument(
        "--config", type=Path,
        help="original dataset config; enables importing evaluation evidence as well",
    )
    subset = sub.add_parser("derive-subset", help="derive a report-only subset from a completed run")
    subset.add_argument("--source-run", type=Path, required=True)
    subset.add_argument("--selection-manifest", type=Path, required=True)
    subset.add_argument("--output-run", type=Path, required=True)
    subset.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-plugins":
            print(json.dumps(plugin_inventory(), ensure_ascii=False, indent=2))
            return 0
        if args.command == "import-run":
            import_config = load_config(args.config.resolve()) if args.config else None
            base_dir = None
            if import_config is not None:
                config_parent = Path(import_config["_config_path"]).resolve().parent
                configured_root = import_config.get("workspace_root")
                base_dir = (
                    resolve_path(configured_root, config_parent)
                    if configured_root else Path.cwd().resolve()
                )
            if args.cache_dir:
                cache_dir = args.cache_dir.resolve()
            elif import_config is not None and base_dir is not None:
                cache_dir = resolve_path(import_config["output"]["cache"], base_dir)
            else:
                raise ValueError("import-run requires --cache-dir or --config")
            print(json.dumps(import_run(
                args.run_dir, cache_dir, config=import_config, base_dir=base_dir
            ), ensure_ascii=False, indent=2))
            return 0
        if args.command == "derive-subset":
            print(json.dumps(derive_subset(
                args.source_run, args.selection_manifest, args.output_run, force=args.force
            ), ensure_ascii=False, indent=2))
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
        if args.command == "create-selection-manifest":
            output = args.output.resolve()
            if output.exists() and not args.force:
                raise FileExistsError(f"Selection manifest already exists: {output}; use --force to replace it")
            config_parent = Path(config["_config_path"]).resolve().parent
            configured_root = config.get("workspace_root")
            base_dir = (
                resolve_path(configured_root, config_parent)
                if configured_root
                else Path.cwd().resolve()
            )
            samples = []
            for entry in config["datasets"]:
                samples.extend(create_dataset(entry, base_dir).iter_samples())
            manifest = build_selection_manifest(samples)
            manifest["created_at"] = datetime.now(timezone.utc).isoformat()
            manifest["source_config_hash"] = config["_config_hash"]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps({
                "created": str(output),
                "sample_count": manifest["sample_count"],
                "selection_hash": manifest["selection_hash"],
            }, ensure_ascii=False, indent=2))
            return 0
        if args.command == "validate-config":
            print(json.dumps({"valid": True, "config_hash": config["_config_hash"]}, indent=2))
            return 0
        runner = EvaluationRunner(
            config,
            run_dir=args.run_dir,
            resume=getattr(args, "resume", False),
            evaluate_only=args.command == "evaluate",
            generate_only=args.command == "generate",
        )
        if args.command == "validate-dataset":
            result = runner.validate_datasets(force=args.force)
        elif args.command == "generate":
            result = runner.generate()
        else:
            result = runner.run()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
