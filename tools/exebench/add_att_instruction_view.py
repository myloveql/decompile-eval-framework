#!/usr/bin/env python3
"""Add a clean GNU objdump AT&T instruction view to the finalized 1100 dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from decomp_eval.datasets.exebench import externalize_target, sanitize_dependencies
from objdump_instruction_view import clean_objdump_att


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build(sample: dict, timeout: int):
    name = sample["function_name"]
    source = externalize_target(sample["source"]["code"], name)
    deps = sanitize_dependencies(sample["evaluation"].get("dependencies", ""), for_cpp_wrapper=False)
    with tempfile.TemporaryDirectory(prefix="eb1100_att_") as temporary:
        root = Path(temporary)
        (root / "candidate.c").write_text(deps + "\n" + source + "\n", encoding="utf-8")
        compiled = subprocess.run(
            ["gcc", "-c", f'-{sample["optimization"]}', "-std=gnu11", "-fcommon", "-w",
             "-o", "candidate.o", "candidate.c"],
            cwd=root, capture_output=True, text=True, timeout=timeout,
        )
        if compiled.returncode:
            raise RuntimeError(f'{sample["sample_id"]}: {compiled.stderr[-2000:]}')
        disassembled = subprocess.run(
            ["objdump", "-dr", "--no-show-raw-insn", f"--disassemble={name}", "candidate.o"],
            cwd=root, capture_output=True, text=True, timeout=timeout,
        )
        if disassembled.returncode:
            raise RuntimeError(f'{sample["sample_id"]}: {disassembled.stderr[-2000:]}')
        result = clean_objdump_att(disassembled.stdout)
        if result.function_name != name:
            raise RuntimeError(f'{sample["sample_id"]}: symbol mismatch {result.function_name!r}')
        return sample["sample_id"], result


def main() -> int:
    if os.name == "nt":
        raise SystemExit("Run this tool inside Linux/WSL")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    document = json.loads(args.dataset.resolve().read_text(encoding="utf-8"))
    samples = document["samples"]
    if len(samples) != 1100:
        raise SystemExit(f"expected 1100 samples, found {len(samples)}")
    built = {}
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(build, row, args.timeout): row["sample_id"] for row in samples}
        for future in as_completed(futures):
            sample_id, result = future.result()
            built[sample_id] = result
            if len(built) % 100 == 0:
                print(f"[{len(built)}/{len(samples)}]", flush=True)
    totals = Counter()
    by_opt = Counter()
    for row in samples:
        result = built[row["sample_id"]]
        asm = row["assembly"]
        asm["objdump_att_instruction_only"] = result.text
        asm["objdump_att_instruction_only_sha256"] = sha256_text(result.text)
        asm["objdump_att_instruction_only_syntax"] = "AT&T"
        asm["objdump_att_instruction_only_origin"] = (
            "generated with objdump -dr --no-show-raw-insn; addresses/headers removed; "
            "PC32/PLT32 relocations merged into symbolic operands"
        )
        totals.update(instructions=result.instruction_count, relocations=result.relocation_count,
                      labels=result.internal_label_count)
        by_opt[row["optimization"]] += result.instruction_count
    document["att_instruction_only_view"] = {
        "field": "samples[].assembly.objdump_att_instruction_only",
        "source": "fresh objdump -dr --no-show-raw-insn output",
        "syntax": "AT&T", "samples": len(samples), "instructions": totals["instructions"],
        "instructions_by_optimization": dict(sorted(by_opt.items())),
        "relocations_merged": totals["relocations"], "internal_labels_generated": totals["labels"],
        "policy": "Same symbolic instruction-only policy as the Intel view; no addresses or raw bytes.",
    }
    output = args.output.resolve()
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(json.dumps({"output": str(output), **document["att_instruction_only_view"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
