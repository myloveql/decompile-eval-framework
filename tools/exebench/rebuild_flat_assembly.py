#!/usr/bin/env python3
"""Recompile and rebuild every assembly view in the self-contained flat dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from decomp_eval.datasets.exebench import externalize_target, sanitize_dependencies
from objdump_instruction_view import clean_objdump_intel


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 60):
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_objdump_header(value: str) -> str:
    lines = value.splitlines()
    for index, line in enumerate(lines):
        if "file format" in line and "candidate.o:" in line:
            lines[index] = re.sub(r"^.*candidate\.o:", "candidate.o:", line)
            break
    return "\n".join(lines) + "\n"


def extract_target_assembly(assembly: str, function_name: str) -> str:
    lines = assembly.splitlines(keepends=True)
    start = next(
        (index for index, line in enumerate(lines) if line.strip() == f"{function_name}:"),
        None,
    )
    if start is None:
        raise ValueError(f"target label not found in GCC assembly: {function_name}")
    end = next(
        (
            index + 1
            for index in range(start, len(lines))
            if lines[index].lstrip().startswith(".size")
            and re.search(rf"\.size\s+{re.escape(function_name)}\s*,", lines[index])
        ),
        len(lines),
    )
    prefix = [
        line
        for line in lines[:start]
        if re.match(rf"\s*\.(globl|type)\s+{re.escape(function_name)}(?:\s|,|$)", line)
    ]
    return "".join(prefix + lines[start:end])


def rebuild_sample(sample: dict[str, Any], timeout: int) -> tuple[str, dict[str, Any], dict[str, int]]:
    function_name = sample["function_name"]
    optimization = sample["optimization"]
    source_code = externalize_target(sample["source"]["code"], function_name)
    dependencies = sanitize_dependencies(
        sample["evaluation"].get("dependencies", ""),
        for_cpp_wrapper=False,
    )

    with tempfile.TemporaryDirectory(prefix="eb1100_rebuild_") as temp_name:
        temp = Path(temp_name)
        source_path = temp / "candidate.c"
        assembly_path = temp / "candidate.s"
        object_path = temp / "candidate.o"
        source_path.write_text(dependencies + "\n" + source_code + "\n", encoding="utf-8")
        common = [f"-{optimization}", "-std=gnu11", "-fcommon", "-w"]

        generated_assembly = run(
            ["gcc", "-S", *common, "-o", str(assembly_path), str(source_path)],
            cwd=temp,
            timeout=timeout,
        )
        if generated_assembly.returncode != 0:
            raise RuntimeError(
                f"{sample['sample_id']}: GCC assembly failed: {generated_assembly.stderr[-3000:]}"
            )
        compiled = run(
            ["gcc", "-c", *common, "-o", str(object_path), str(source_path)],
            cwd=temp,
            timeout=timeout,
        )
        if compiled.returncode != 0:
            raise RuntimeError(
                f"{sample['sample_id']}: object compilation failed: {compiled.stderr[-3000:]}"
            )

        raw = run(
            [
                "objdump", "-dr", "-Mintel", f"--disassemble={function_name}", "candidate.o"
            ],
            cwd=temp,
            timeout=timeout,
        )
        no_raw = run(
            [
                "objdump", "-dr", "-Mintel", "--no-show-raw-insn",
                f"--disassemble={function_name}", "candidate.o",
            ],
            cwd=temp,
            timeout=timeout,
        )
        for kind, result in (("raw", raw), ("no-raw", no_raw)):
            if result.returncode != 0 or f"<{function_name}>:" not in result.stdout:
                raise RuntimeError(
                    f"{sample['sample_id']}: {kind} objdump failed: {result.stderr[-3000:]}"
                )

        full_assembly = assembly_path.read_text(encoding="utf-8", errors="replace")
        target_assembly = extract_target_assembly(full_assembly, function_name)
        raw_objdump = normalize_objdump_header(raw.stdout)
        instruction_only = clean_objdump_intel(no_raw.stdout)
        if instruction_only.function_name != function_name:
            raise RuntimeError(
                f"{sample['sample_id']}: cleaned symbol {instruction_only.function_name!r} "
                f"does not match {function_name!r}"
            )

    old = sample["assembly"]
    assembly = {
        "origin": "recompiled_from_self_contained_record_source_code",
        "architecture": "x86_64",
        "syntax": "GNU assembler AT&T",
        "full_translation_unit_assembly": full_assembly,
        "full_translation_unit_assembly_sha256": sha256_text(full_assembly),
        "gcc_target_assembly": target_assembly,
        "gcc_target_assembly_sha256": sha256_text(target_assembly),
        "objdump_intel_with_relocations": raw_objdump,
        "objdump_intel_sha256": sha256_text(raw_objdump),
        "objdump_intel_instruction_only": instruction_only.text,
        "objdump_intel_instruction_only_sha256": sha256_text(instruction_only.text),
        "objdump_intel_instruction_only_syntax": "Intel",
        "objdump_intel_instruction_only_origin": (
            "generated with objdump -dr -Mintel --no-show-raw-insn; addresses/headers removed; "
            "PC32/PLT32 relocations merged into symbolic operands; raw-byte objdump retained "
            "separately for audit"
        ),
        "upstream_matching_assembly_key": old.get("upstream_matching_assembly_key"),
        "upstream_matching_function_assembly": old.get(
            "upstream_matching_function_assembly"
        ),
    }
    stats = {
        "instructions": instruction_only.instruction_count,
        "relocations": instruction_only.relocation_count,
        "labels": instruction_only.internal_label_count,
    }
    return sample["sample_id"], assembly, stats


def main() -> int:
    if os.name == "nt":
        raise SystemExit("Run this rebuild inside Linux/WSL")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    started = time.perf_counter()
    document = json.loads(args.dataset.resolve().read_text(encoding="utf-8"))
    samples = document["samples"]
    if len(samples) != 1100:
        raise SystemExit(f"expected 1100 samples, found {len(samples)}")

    rebuilt: dict[str, tuple[dict[str, Any], dict[str, int]]] = {}
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(rebuild_sample, sample, args.timeout): sample["sample_id"]
            for sample in samples
        }
        for future in as_completed(futures):
            sample_id = futures[future]
            rebuilt_id, assembly, stats = future.result()
            if rebuilt_id != sample_id:
                raise RuntimeError(f"worker result mismatch: {sample_id} != {rebuilt_id}")
            rebuilt[sample_id] = (assembly, stats)
            if len(rebuilt) % 50 == 0 or len(rebuilt) == len(samples):
                print(f"[{len(rebuilt)}/{len(samples)}] {sample_id}", flush=True)

    if len(rebuilt) != len(samples):
        raise RuntimeError(f"rebuilt only {len(rebuilt)} of {len(samples)} samples")
    totals = Counter()
    by_optimization: Counter[str] = Counter()
    for sample in samples:
        assembly, stats = rebuilt[sample["sample_id"]]
        sample["assembly"] = assembly
        totals.update(stats)
        by_optimization[sample["optimization"]] += stats["instructions"]

    gcc_version = run(["gcc", "--version"]).stdout.splitlines()[0]
    objdump_version = run(["objdump", "--version"]).stdout.splitlines()[0]
    document["platform"] = platform.platform()
    document["assembly_rebuild"] = {
        "method": "self_contained_source_recompile",
        "rebuilt_at": datetime.now(timezone.utc).isoformat(),
        "source_dataset": str(args.dataset.resolve()),
        "gcc": gcc_version,
        "objdump": objdump_version,
        "compiler_flags": ["-std=gnu11", "-fcommon", "-w", "per-sample -O0/-O1/-O2/-O3"],
        "objdump_raw_command": "objdump -dr -Mintel --disassemble=<function> candidate.o",
        "objdump_instruction_command": (
            "objdump -dr -Mintel --no-show-raw-insn --disassemble=<function> candidate.o"
        ),
        "samples": len(samples),
    }
    document["instruction_only_view"] = {
        "field": "samples[].assembly.objdump_intel_instruction_only",
        "source": "fresh objdump --no-show-raw-insn output",
        "syntax": "Intel",
        "samples": len(samples),
        "instructions": totals["instructions"],
        "instructions_by_optimization": dict(sorted(by_optimization.items())),
        "relocations_merged": totals["relocations"],
        "internal_labels_generated": totals["labels"],
        "policy": (
            "Keep function/control-flow labels, mnemonics, operands, global symbols and external "
            "symbols; remove objdump headers, instruction addresses and address comments. Raw "
            "instruction bytes are disabled by objdump before cleaning."
        ),
    }
    # Behavioral validation is deliberately invalidated until the rebuilt file
    # passes validate_assembly_behavior.py --update-dataset.
    document.pop("assembly_behavioral_validation", None)
    for sample in samples:
        sample.pop("assembly_validation", None)

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    print(
        json.dumps(
            {
                "output": str(output),
                "samples": len(samples),
                "instructions": totals["instructions"],
                "relocations_merged": totals["relocations"],
                "internal_labels_generated": totals["labels"],
                "size_bytes": output.stat().st_size,
                "elapsed_seconds": time.perf_counter() - started,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
