#!/usr/bin/env python3
"""Reassemble stored dataset ASM and validate it against every recorded I/O pair."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from decomp_eval.datasets.exebench import sanitize_dependencies
from decomp_eval.datasets.common import strict_equal as strict_diff_io


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def failure(sample: dict[str, Any], reason: str, started: float, **extra: Any) -> dict[str, Any]:
    return {
        "sample_id": sample["sample_id"],
        "legacy_name": sample["legacy_name"],
        "source_group_id": sample["source_group_id"],
        "source_type": sample["source_type"],
        "function_name": sample["function_name"],
        "optimization": sample["optimization"],
        "assemble_pass": False,
        "link_pass": False,
        "behavioral_pass": False,
        "reason": reason,
        "elapsed_seconds": time.perf_counter() - started,
        **extra,
    }


def validate_one(sample: dict[str, Any], exebench_include: Path, timeout: int) -> dict[str, Any]:
    started = time.perf_counter()
    assembly = sample["assembly"]["full_translation_unit_assembly"]
    evaluation = sample["evaluation"]
    io_pairs = evaluation["io_pairs"]
    with tempfile.TemporaryDirectory(prefix="eb1641_asm_") as temp_name:
        temp = Path(temp_name)
        asm_path = temp / "stored.s"
        object_path = temp / "stored.o"
        asm_path.write_text(assembly, encoding="utf-8")
        try:
            assembled = run(["gcc", "-c", "-o", str(object_path), str(asm_path)], timeout)
        except subprocess.TimeoutExpired:
            return failure(sample, "assembly_timeout", started)
        if assembled.returncode != 0:
            return failure(
                sample, "assembly_error", started, assemble_stderr=assembled.stderr[-4000:]
            )

        deps = sanitize_dependencies(
            evaluation.get("dependencies") or "", for_cpp_wrapper=True
        )
        deps_path = temp / "wrapper_deps.c"
        deps_path.write_text(
            deps + f"\nextern {evaluation['function_head_used_by_wrapper']};\n",
            encoding="utf-8",
        )
        wrapper, replacements = re.subn(
            r'extern\s*"C"\s*\{\s.*?\s*\}',
            f'extern "C"\n{{\n#include "{deps_path}"\n}}',
            evaluation["executable_wrapper"],
            count=1,
            flags=re.DOTALL,
        )
        if replacements != 1:
            return failure(sample, "wrapper_rewrite_failed", started, assemble_pass=True)
        wrapper_path = temp / "wrapper.cpp"
        wrapper_path.write_text(wrapper, encoding="utf-8")
        exe_path = temp / "stored_assembly.x"
        try:
            linked = run(
                [
                    "g++",
                    "-fpermissive",
                    "-O0",
                    "-o",
                    str(exe_path),
                    str(wrapper_path),
                    str(object_path),
                    f"-I{exebench_include}",
                    "-lm",
                ],
                timeout,
            )
        except subprocess.TimeoutExpired:
            return failure(sample, "assembly_link_timeout", started, assemble_pass=True)
        if linked.returncode != 0:
            return failure(
                sample,
                "assembly_link_error",
                started,
                assemble_pass=True,
                link_stderr=linked.stderr[-4000:],
            )

        passed = 0
        mismatches = 0
        runtime_errors = 0
        first_mismatch = None
        first_runtime_error = None
        for index, pair in enumerate(io_pairs):
            input_path = temp / f"input_{index}.json"
            output_path = temp / f"output_{index}.json"
            input_path.write_text(json.dumps(pair.get("input", {})), encoding="utf-8")
            try:
                executed = run([str(exe_path), str(input_path), str(output_path)], timeout)
                if executed.returncode != 0 or not output_path.exists():
                    runtime_errors += 1
                    if first_runtime_error is None:
                        first_runtime_error = {
                            "index": index,
                            "returncode": executed.returncode,
                            "stderr": executed.stderr[-2000:],
                        }
                    continue
                actual = json.loads(output_path.read_text(encoding="utf-8"))
            except subprocess.TimeoutExpired:
                runtime_errors += 1
                if first_runtime_error is None:
                    first_runtime_error = {"index": index, "error": "timeout"}
                continue
            except (OSError, json.JSONDecodeError) as error:
                runtime_errors += 1
                if first_runtime_error is None:
                    first_runtime_error = {"index": index, "error": str(error)}
                continue
            expected = pair.get("output", {})
            if strict_diff_io(actual, expected):
                passed += 1
            else:
                mismatches += 1
                if first_mismatch is None:
                    first_mismatch = {"index": index, "expected": expected, "actual": actual}

        behavioral_pass = passed == len(io_pairs) and not mismatches and not runtime_errors
        reason = "runtime_error" if runtime_errors else ("output_mismatch" if mismatches else None)
        return {
            "sample_id": sample["sample_id"],
            "legacy_name": sample["legacy_name"],
            "source_group_id": sample["source_group_id"],
            "source_type": sample["source_type"],
            "function_name": sample["function_name"],
            "optimization": sample["optimization"],
            "assemble_pass": True,
            "link_pass": True,
            "behavioral_pass": behavioral_pass,
            "reason": reason,
            "tests_total": len(io_pairs),
            "tests_passed": passed,
            "tests_mismatched": mismatches,
            "tests_runtime_error": runtime_errors,
            "first_mismatch": first_mismatch,
            "first_runtime_error": first_runtime_error,
            "elapsed_seconds": time.perf_counter() - started,
        }


def main() -> int:
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
    parser.add_argument("--include-path", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--update-dataset",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Write concise per-sample assembly validation status back into the dataset.",
    )
    args = parser.parse_args()
    if os.name == "nt":
        raise SystemExit("Run inside Linux/WSL")
    dataset_path = args.dataset.resolve()
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    samples = dataset["samples"]
    if len(samples) != 1100:
        raise SystemExit(f"Expected 1100 samples, found {len(samples)}")
    exebench_include = args.include_path.resolve()

    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(validate_one, sample, exebench_include, args.timeout): sample
            for sample in samples
        }
        for future in as_completed(futures):
            sample = futures[future]
            try:
                result = future.result()
            except Exception as error:
                result = failure(sample, "validator_exception", time.perf_counter(), error=repr(error))
            results.append(result)
            if len(results) % 50 == 0 or len(results) == len(samples):
                print(
                    f"[{len(results)}/{len(samples)}] {result['legacy_name']}: "
                    f"{result['reason'] or 'pass'}",
                    flush=True,
                )

    by_optimization: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "behavioral_pass": 0}
    )
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        by_optimization[row["optimization"]]["total"] += 1
        by_optimization[row["optimization"]]["behavioral_pass"] += int(row["behavioral_pass"])
        by_group[row["source_group_id"]].append(row)
    assembled_count = sum(row["assemble_pass"] for row in results)
    linked_count = sum(row["link_pass"] for row in results)
    passed_count = sum(row["behavioral_pass"] for row in results)
    all_groups_pass = sum(all(row["behavioral_pass"] for row in rows) for rows in by_group.values())
    report_relative = str(args.output.resolve())
    report = {
        "schema_version": 1,
        "method": "stored_assembly_behavioral_validation",
        "dataset": str(dataset_path),
        "uses_stored_full_translation_unit_assembly": True,
        "statistics": {
            "total": len(results),
            "assemble_pass": assembled_count,
            "link_pass": linked_count,
            "behavioral_pass": passed_count,
            "behavioral_pass_rate": passed_count / len(results),
            "failure_reasons": dict(
                sorted(Counter(row["reason"] or "pass" for row in results).items())
            ),
            "by_optimization": dict(sorted(by_optimization.items())),
            "source_groups": len(by_group),
            "all_optimizations_pass_groups": all_groups_pass,
            "elapsed_seconds": time.perf_counter() - started,
        },
        "results": sorted(results, key=lambda row: row["legacy_name"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.update_dataset:
        results_by_id = {row["sample_id"]: row for row in results}
        for sample in samples:
            result = results_by_id[sample["sample_id"]]
            sample["assembly_validation"] = {
                "report": report_relative,
                "validated_full_assembly_sha256": sample["assembly"][
                    "full_translation_unit_assembly_sha256"
                ],
                "assembled": result["assemble_pass"],
                "linked": result["link_pass"],
                "behavioral_pass": result["behavioral_pass"],
                "tests_total": result.get("tests_total", 0),
                "tests_passed": result.get("tests_passed", 0),
                "reason": result["reason"],
            }
        dataset["assembly_behavioral_validation"] = {
            "report": report_relative,
            "total": len(results),
            "behavioral_pass": passed_count,
            "all_optimizations_pass_groups": all_groups_pass,
        }
        temp_output = dataset_path.with_suffix(dataset_path.suffix + ".tmp")
        temp_output.write_text(
            json.dumps(dataset, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temp_output.replace(dataset_path)

    print(json.dumps(report["statistics"], ensure_ascii=False, indent=2))
    print(f"saved={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
