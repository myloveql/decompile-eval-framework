#!/usr/bin/env python3
"""Validate the flat 1100-record source/assembly/evaluation dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256_text(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--source-report", type=Path)
    parser.add_argument("--assembly-report", type=Path)
    parser.add_argument(
        "--asset-root", type=Path, required=True,
        help="Root used to resolve binary.path entries stored in the dataset.",
    )
    args = parser.parse_args()
    dataset_path = args.dataset.resolve()
    asset_root = args.asset_root.resolve()
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    samples = dataset.get("samples", [])
    ghidra_view = dataset.get("ghidra_pseudocode_view")
    errors: list[str] = []

    if dataset.get("schema") != "exebench_flat_source_dataset" or dataset.get("schema_version") != 1:
        errors.append("invalid flat dataset schema")
    if len(samples) != 1100:
        errors.append(f"expected 1100 samples, found {len(samples)}")
    sample_ids = [row.get("sample_id") for row in samples]
    legacy_names = [row.get("legacy_name") for row in samples]
    if len(set(sample_ids)) != len(samples) or len(set(legacy_names)) != len(samples):
        errors.append("sample_id or legacy_name is not unique")
    optimization_counts = Counter(row.get("optimization") for row in samples)
    if optimization_counts != Counter({"O0": 275, "O1": 275, "O2": 275, "O3": 275}):
        errors.append(f"unexpected optimization counts: {dict(optimization_counts)}")

    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if args.source_report:
        report = json.loads(args.source_report.resolve().read_text(encoding="utf-8"))
        report_pass_ids = {
            row["sample_id"] for row in report["results"] if row["behavioral_pass"]
        }
        if set(sample_ids) != report_pass_ids:
            errors.append("dataset samples differ from the 1100 passing report results")
    assembly_results = None
    if args.assembly_report:
        assembly_report = json.loads(
            args.assembly_report.resolve().read_text(encoding="utf-8")
        )
        assembly_results = {row["sample_id"]: row for row in assembly_report["results"]}
        assembly_stats = assembly_report["statistics"]
        if (
            assembly_stats.get("total") != 1100
            or assembly_stats.get("assemble_pass") != 1100
            or assembly_stats.get("link_pass") != 1100
            or assembly_stats.get("behavioral_pass") != 1100
        ):
            errors.append("assembly behavior report is not 1100/1100")

    for row in samples:
        sample_id = row.get("sample_id", "<missing>")
        by_group[row.get("source_group_id")].append(row)
        source = row.get("source", {})
        evaluation = row.get("evaluation", {})
        assembly = row.get("assembly", {})
        binary_data = row.get("binary", {})
        if ghidra_view is not None:
            pseudocode = (row.get("decompilation") or {}).get("ghidra") or {}
            code = pseudocode.get("code", "")
            if not code or sha256_text(code) != pseudocode.get("sha256"):
                errors.append(f"{sample_id}: Ghidra pseudocode missing or hash mismatch")
            if pseudocode.get("producer") != "ghidra" or not pseudocode.get("version"):
                errors.append(f"{sample_id}: Ghidra producer/version metadata invalid")
            if pseudocode.get("function_name") != row.get("function_name"):
                errors.append(f"{sample_id}: Ghidra target function mismatch")
            if pseudocode.get("input_kind") != "target-object":
                errors.append(f"{sample_id}: Ghidra input kind is not target-object")
            if not re.fullmatch(r"[0-9a-f]{64}", pseudocode.get("input_binary_sha256", "")):
                errors.append(f"{sample_id}: Ghidra input object hash invalid")
        if not source.get("code") or sha256_text(source.get("code", "")) != source.get("code_sha256"):
            errors.append(f"{sample_id}: source code missing or hash mismatch")
        dependencies = evaluation.get("dependencies", "")
        wrapper = evaluation.get("executable_wrapper", "")
        io_pairs = evaluation.get("io_pairs") or []
        if sha256_text(dependencies) != evaluation.get("dependencies_sha256"):
            errors.append(f"{sample_id}: dependencies hash mismatch")
        if not wrapper or sha256_text(wrapper) != evaluation.get("executable_wrapper_sha256"):
            errors.append(f"{sample_id}: wrapper missing or hash mismatch")
        if not io_pairs or len(io_pairs) != evaluation.get("io_pair_count"):
            errors.append(f"{sample_id}: I/O pairs missing or count mismatch")
        if sha256_json(io_pairs) != evaluation.get("io_pairs_sha256"):
            errors.append(f"{sample_id}: I/O pairs hash mismatch")
        if evaluation.get("method") != "ground_truth_c_source" or evaluation.get("passed") is not True:
            errors.append(f"{sample_id}: evaluation status is not source-passed")
        if evaluation.get("uses_reference_assembly") is not False:
            errors.append(f"{sample_id}: source evaluation incorrectly uses reference assembly")
        expected_flag = f"-{row.get('optimization')}"
        if expected_flag not in evaluation.get("compiler_flags", []):
            errors.append(f"{sample_id}: optimization compiler flag mismatch")
        target_asm = assembly.get("gcc_target_assembly", "")
        full_asm = assembly.get("full_translation_unit_assembly", "")
        objdump = assembly.get("objdump_intel_with_relocations", "")
        instruction_only = assembly.get("objdump_intel_instruction_only", "")
        att_instruction_only = assembly.get("objdump_att_instruction_only", "")
        if not full_asm or sha256_text(full_asm) != assembly.get(
            "full_translation_unit_assembly_sha256"
        ):
            errors.append(f"{sample_id}: full translation-unit assembly missing or hash mismatch")
        if not target_asm or sha256_text(target_asm) != assembly.get("gcc_target_assembly_sha256"):
            errors.append(f"{sample_id}: GCC target assembly missing or hash mismatch")
        if not objdump or sha256_text(objdump) != assembly.get("objdump_intel_sha256"):
            errors.append(f"{sample_id}: objdump disassembly missing or hash mismatch")
        if not instruction_only or sha256_text(instruction_only) != assembly.get(
            "objdump_intel_instruction_only_sha256"
        ):
            errors.append(f"{sample_id}: instruction-only disassembly missing or hash mismatch")
        else:
            if not instruction_only.startswith(f"{row.get('function_name')}:\n"):
                errors.append(f"{sample_id}: instruction-only target label mismatch")
            if re.search(r"^\s*[0-9a-fA-F]+:\s", instruction_only, flags=re.MULTILINE):
                errors.append(f"{sample_id}: instruction-only view still has addresses")
            if "R_X86_64_" in instruction_only:
                errors.append(f"{sample_id}: instruction-only view still has relocation records")
            if re.search(r"^\s*\.(?:file|text|section|globl|type|size|cfi|ident)", instruction_only, re.MULTILINE):
                errors.append(f"{sample_id}: instruction-only view still has assembler directives")
        if assembly.get("objdump_intel_instruction_only_syntax") != "Intel":
            errors.append(f"{sample_id}: instruction-only syntax is not Intel")
        if not att_instruction_only or sha256_text(att_instruction_only) != assembly.get(
            "objdump_att_instruction_only_sha256"
        ):
            errors.append(f"{sample_id}: AT&T instruction-only view missing or hash mismatch")
        elif not att_instruction_only.startswith(f"{row.get('function_name')}:\n"):
            errors.append(f"{sample_id}: AT&T target label mismatch")
        elif re.search(r"^\s*[0-9a-fA-F]+:\s", att_instruction_only, flags=re.MULTILINE):
            errors.append(f"{sample_id}: AT&T view still has addresses")
        if assembly.get("objdump_att_instruction_only_syntax") != "AT&T":
            errors.append(f"{sample_id}: AT&T syntax marker is invalid")
        if f"<{row.get('function_name')}>:" not in objdump:
            errors.append(f"{sample_id}: target symbol absent from disassembly")
        assembly_validation = row.get("assembly_validation", {})
        if assembly_results is not None:
            result = assembly_results.get(sample_id)
            if result is None or not result.get("behavioral_pass"):
                errors.append(f"{sample_id}: missing passing result in assembly report")
        if not (
            assembly_validation.get("assembled")
            and assembly_validation.get("linked")
            and assembly_validation.get("behavioral_pass")
            and assembly_validation.get("tests_total")
            == assembly_validation.get("tests_passed")
            == len(io_pairs)
        ):
            errors.append(f"{sample_id}: embedded assembly validation is not fully passing")
        if assembly_validation.get("validated_full_assembly_sha256") != assembly.get(
            "full_translation_unit_assembly_sha256"
        ):
            errors.append(f"{sample_id}: validated assembly hash differs from stored assembly")
        binary = asset_root / binary_data.get("path", "")
        if not binary.exists() or sha256_file(binary) != binary_data.get("sha256"):
            errors.append(f"{sample_id}: binary path/hash mismatch")

    if len(by_group) != 275:
        errors.append(f"expected 275 source groups, found {len(by_group)}")
    for group_id, rows in by_group.items():
        if {row["optimization"] for row in rows} != {"O0", "O1", "O2", "O3"}:
            errors.append(f"{group_id}: incomplete optimization group")

    instruction_view = dataset.get("instruction_only_view", {})
    instruction_total = sum(
        line.startswith("    ")
        for row in samples
        for line in row.get("assembly", {}).get("objdump_intel_instruction_only", "").splitlines()
    )
    relocation_total = sum(
        "R_X86_64_" in line
        for row in samples
        for line in row.get("assembly", {}).get("objdump_intel_with_relocations", "").splitlines()
    )
    label_total = sum(
        line.startswith(".L_")
        for row in samples
        for line in row.get("assembly", {}).get("objdump_intel_instruction_only", "").splitlines()
    )
    if instruction_view.get("samples") != len(samples):
        errors.append("instruction-only metadata sample count mismatch")
    if instruction_view.get("instructions") != instruction_total:
        errors.append("instruction-only metadata instruction count mismatch")
    if instruction_view.get("relocations_merged") != relocation_total:
        errors.append("instruction-only metadata relocation count mismatch")
    if instruction_view.get("internal_labels_generated") != label_total:
        errors.append("instruction-only metadata label count mismatch")
    if ghidra_view is not None:
        ghidra_count = sum(
            bool(((row.get("decompilation") or {}).get("ghidra") or {}).get("code"))
            for row in samples
        )
        if ghidra_view.get("samples_total") != len(samples):
            errors.append("Ghidra metadata total sample count mismatch")
        if ghidra_view.get("samples_available") != ghidra_count:
            errors.append("Ghidra metadata available sample count mismatch")
        if ghidra_count != len(samples) or ghidra_view.get("failures"):
            errors.append("Ghidra pseudocode view is incomplete")

    validation = {
        "valid": not errors,
        "dataset": str(dataset_path),
        "samples": len(samples),
        "source_groups": len(by_group),
        "optimizations": dict(sorted(optimization_counts.items())),
        "all_have_source": sum(bool(row.get("source", {}).get("code")) for row in samples),
        "all_have_evaluation_io": sum(bool(row.get("evaluation", {}).get("io_pairs")) for row in samples),
        "all_have_generated_assembly": sum(
            bool(row.get("assembly", {}).get("gcc_target_assembly")) for row in samples
        ),
        "all_have_instruction_only_assembly": sum(
            bool(row.get("assembly", {}).get("objdump_intel_instruction_only")) for row in samples
        ),
        "all_have_att_instruction_only_assembly": sum(
            bool(row.get("assembly", {}).get("objdump_att_instruction_only")) for row in samples
        ),
        "all_have_behavior_validated_assembly": sum(
            bool(row.get("assembly_validation", {}).get("behavioral_pass")) for row in samples
        ),
        "all_have_ghidra_pseudocode": sum(
            bool(((row.get("decompilation") or {}).get("ghidra") or {}).get("code"))
            for row in samples
        ),
        "errors": errors,
    }
    print(json.dumps(validation, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
