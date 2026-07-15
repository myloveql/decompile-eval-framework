#!/usr/bin/env python3
"""Generate a fixed Ghidra pseudocode view and write it into an ExeBench flat dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from decomp_eval.backends.ghidra import GhidraHeadlessBackend
from decomp_eval.datasets.exebench import externalize_target, sanitize_dependencies
from decomp_eval.models import AssemblyInput, BinaryInput, DecompileRequest
from decomp_eval.util import resolve_path, sha256_text


VIEW_NAME = "ghidra"


def atomic_write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_target_object(row: dict, root: Path) -> tuple[BinaryInput | None, str | None]:
    sample_root = root / row["sample_id"].replace(":", "_")
    sample_root.mkdir(parents=True)
    source = externalize_target(row["source"]["code"], row["function_name"])
    dependencies = sanitize_dependencies(
        row["evaluation"].get("dependencies", ""), for_cpp_wrapper=False
    )
    source_path = sample_root / "target.c"
    object_path = sample_root / "target.o"
    source_path.write_text(dependencies + "\n" + source + "\n", encoding="utf-8")
    command = [
        "gcc", "-c", f'-{row["optimization"]}', "-std=gnu11", "-fcommon", "-w",
        "-o", str(object_path), str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode or not object_path.is_file():
        return None, "target_object_compile_error: " + completed.stderr[-1000:]
    return BinaryInput(
        path=str(object_path), sha256=sha256_file(object_path),
        format="ELF relocatable", architecture="x86_64",
    ), None


def request_for(
    row: dict, workspace_root: Path, binary_override: BinaryInput | None = None
) -> DecompileRequest:
    binary_record = row.get("binary") or {}
    binary_path = binary_record.get("path")
    return DecompileRequest(
        dataset_id="exebench",
        split="benchmark",
        sample_id=row["sample_id"],
        source_group_id=row["source_group_id"],
        function_name=row["function_name"],
        language=row.get("source_metadata", {}).get("language", "c"),
        optimization=row["optimization"],
        assembly=AssemblyInput(text="", syntax="", view="none"),
        metadata={},
        binary=binary_override or (BinaryInput(
            path=str(resolve_path(binary_path, workspace_root)) if binary_path else "",
            sha256=binary_record.get("sha256"),
            format=binary_record.get("format", "ELF"),
            architecture=binary_record.get("architecture", "x86_64"),
        ) if binary_path else None),
    )


def generate_batch(
    backend: GhidraHeadlessBackend,
    rows: list[dict],
    workspace_root: Path,
    artifact_root: Path | None,
    binary_view: str,
) -> list[tuple[str, dict | None, str | None]]:
    with tempfile.TemporaryDirectory(prefix="exebench_ghidra_") as temporary:
        root = Path(temporary)
        requests = []
        request_rows = []
        records: list[tuple[str, dict | None, str | None]] = []
        for row in rows:
            binary = None
            if binary_view == "target-object":
                binary, error = build_target_object(row, root / "objects")
                if error:
                    records.append((row["sample_id"], None, error))
                    continue
            requests.append(request_for(row, workspace_root, binary))
            request_rows.append(row)
        if artifact_root:
            workdirs = [
                artifact_root / row["sample_id"].replace(":", "_") for row in request_rows
            ]
            for workdir in workdirs:
                shutil.rmtree(workdir, ignore_errors=True)
                workdir.mkdir(parents=True)
        else:
            workdirs = [root / f"sample_{index:06d}" for index in range(len(request_rows))]
        results = backend.decompile_many(requests, workdirs)
    for row, request, result in zip(request_rows, requests, results):
        sample_id = row["sample_id"]
        if not result.success or not result.code.strip():
            records.append((sample_id, None, result.reason or "decompile_empty_output"))
            continue
        code = result.code.strip() + "\n"
        records.append((sample_id, {
            "code": code,
            "sha256": sha256_text(code),
            "producer": "ghidra",
            "version": result.backend_version,
            "function_name": row["function_name"],
            "input_kind": binary_view,
            "input_binary_sha256": request.binary.sha256,
            "input_binary_format": request.binary.format,
            "compiler_optimization": row["optimization"],
        }, None))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--ghidra-path", required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument(
        "--binary-view", choices=["target-object", "dataset-binary"],
        default="target-object",
    )
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--analysis-timeout", type=int, default=120)
    parser.add_argument("--checkpoint-every", type=int, default=25)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()

    dataset = args.dataset.resolve()
    output = args.output.resolve()
    workspace_root = args.workspace_root.resolve()
    source = output if args.resume and output.exists() else dataset
    document = json.loads(source.read_text(encoding="utf-8"))
    rows = document["samples"]
    selected = []
    for row in rows:
        existing = (row.get("decompilation") or {}).get(VIEW_NAME)
        existing_code = existing if isinstance(existing, str) else (existing or {}).get("code")
        if existing_code and not args.overwrite:
            continue
        selected.append(row)
        if args.limit is not None and len(selected) >= args.limit:
            break

    backend = GhidraHeadlessBackend({
        "id": "ghidra-dataset-builder",
        "ghidra_path": args.ghidra_path,
        "timeout": args.timeout,
        "analysis_timeout": args.analysis_timeout,
        "verify_binary_hash": True,
    }, base_dir=workspace_root)
    backend.prepare([])
    artifact_root = args.artifact_root.resolve() if args.artifact_root else None
    if artifact_root:
        artifact_root.mkdir(parents=True, exist_ok=True)

    completed = 0
    failures: dict[str, str] = {}
    by_id = {row["sample_id"]: row for row in rows}
    batch_size = max(1, args.batch_size)
    batches = [selected[index:index + batch_size] for index in range(0, len(selected), batch_size)]
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(
                generate_batch, backend, batch, workspace_root, artifact_root, args.binary_view
            ): batch
            for batch in batches
        }
        for future in as_completed(futures):
            try:
                batch_results = future.result()
            except Exception as exception:
                batch_results = [
                    (row["sample_id"], None, f"builder_exception: {exception!r}")
                    for row in futures[future]
                ]
            for sample_id, record, error in batch_results:
                if record:
                    by_id[sample_id].setdefault("decompilation", {})[VIEW_NAME] = record
                else:
                    failures[sample_id] = error or "unknown_error"
                completed += 1
                print(
                    f"[{completed}/{len(selected)}] {sample_id}: {error or 'ok'}",
                    flush=True,
                )
            if completed % max(1, args.checkpoint_every) < len(batch_results):
                atomic_write(output, document)

    available = sum(
        bool(((row.get("decompilation") or {}).get(VIEW_NAME) or {}).get("code"))
        for row in rows
    )
    document["ghidra_pseudocode_view"] = {
        "schema_version": 1,
        "field": "samples[].decompilation.ghidra.code",
        "producer": "ghidra",
        "version": backend.version,
        "input_kind": args.binary_view,
        "samples_total": len(rows),
        "samples_available": available,
        "failures": failures,
    }
    atomic_write(output, document)
    print(json.dumps(document["ghidra_pseudocode_view"], ensure_ascii=False, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
