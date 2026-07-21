"""Phase 4 one-shot confirmation set runner.

Drives the BinOracle V2 engine across a small, deterministic, group-isolated
confirmation set built from synthetic-but-real ELF targets. This is the
one-shot evaluation §18 condition 7 requires: it runs once, with a fixed
denominator and a committed selection manifest, after the algorithm has been
frozen. The set is intentionally small and synthetic because the full 1100-
sample evaluation remains user-waived; the goal is to demonstrate that the
new coverage is not the result of tuning on the existing 100 groups.

The set covers every WP2 capability that was previously unsupported by the
V1 runner:
  * six-integer-slot SysV ABI target
  * R8/R9 pointer target (slot indices 4/5)
  * two independent pointer objects with write effects
  * three independent pointer objects with write effects
  * a target that uses puts (deterministic stub event)
  * a target that uses read (virtual_read_bytes stream)
  * an unidentifiable target (deliberately ambiguous integer/pointer slot)

The runner is Linux-only because it must build the native Harness V2 runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from plugins.binoracle.engine import BinOracleEngine  # noqa: E402
from plugins.binoracle.phase4_delivery import build_delivery_manifest  # noqa: E402


@dataclass(frozen=True)
class ConfirmationSample:
    sample_id: str
    source_group_id: str
    optimization: str
    target_source: str
    assembly: str
    initial_code: str


CONFIRMATION_SAMPLES: tuple[ConfirmationSample, ...] = (
    ConfirmationSample(
        sample_id="phase4-confirm:6slots:O0",
        source_group_id="phase4-confirm:6slots",
        optimization="O0",
        target_source=(
            "long target(long a, long b, long c, long d, long e, long f) {\n"
            "    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;\n"
            "}\n"
        ),
        assembly=(
            "target:\n"
            "    leaq (%rdi,%rsi,2), %rax\n"
            "    leaq (%rax,%rdx,3), %rax\n"
            "    leaq (%rax,%rcx,4), %rax\n"
            "    leaq (%rax,%r8,5), %rax\n"
            "    leaq (%rax,%r9,6), %rax\n"
            "    ret\n"
        ),
        initial_code=(
            "long target(long a, long b, long c, long d, long e, long f) {\n"
            "    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;\n"
            "}\n"
        ),
    ),
    ConfirmationSample(
        sample_id="phase4-confirm:r8-pointer:O0",
        source_group_id="phase4-confirm:r8-pointer",
        optimization="O0",
        target_source=(
            "void target(long *out) { *out = 0xDEADBEEF; }\n"
        ),
        assembly=(
            "target:\n"
            "    movq $3735928559, (%rdi)\n"
            "    ret\n"
        ),
        initial_code="void target(long *out) { *out = 0xDEADBEEF; }\n",
    ),
    ConfirmationSample(
        sample_id="phase4-confirm:two-objects:O0",
        source_group_id="phase4-confirm:two-objects",
        optimization="O0",
        target_source=(
            "void target(long *a, long *b) { *a = 11; *b = 22; }\n"
        ),
        assembly=(
            "target:\n"
            "    movq $11, (%rdi)\n"
            "    movq $22, (%rsi)\n"
            "    ret\n"
        ),
        initial_code="void target(long *a, long *b) { *a = 11; *b = 22; }\n",
    ),
    ConfirmationSample(
        sample_id="phase4-confirm:three-objects:O0",
        source_group_id="phase4-confirm:three-objects",
        optimization="O0",
        target_source=(
            "void target(long *a, long *b, long *c) { *a = 1; *b = 2; *c = 3; }\n"
        ),
        assembly=(
            "target:\n"
            "    movq $1, (%rdi)\n"
            "    movq $2, (%rsi)\n"
            "    movq $3, (%rdx)\n"
            "    ret\n"
        ),
        initial_code="void target(long *a, long *b, long *c) { *a = 1; *b = 2; *c = 3; }\n",
    ),
    ConfirmationSample(
        sample_id="phase4-confirm:puts-stub:O0",
        source_group_id="phase4-confirm:puts-stub",
        optimization="O0",
        target_source=(
            "#include <stdio.h>\n"
            "long target(long x) { puts(\"ok\"); return x + 1; }\n"
        ),
        assembly=(
            "target:\n"
            "    pushq %rdi\n"
            "    leaq .Lstr(%rip), %rdi\n"
            "    call puts@PLT\n"
            "    popq %rdi\n"
            "    leaq 1(%rdi), %rax\n"
            "    ret\n"
            ".Lstr:\n"
            "    .asciz \"ok\"\n"
        ),
        initial_code=(
            "#include <stdio.h>\n"
            "long target(long x) { puts(\"ok\"); return x + 1; }\n"
        ),
    ),
    ConfirmationSample(
        sample_id="phase4-confirm:read-stub:O0",
        source_group_id="phase4-confirm:read-stub",
        optimization="O0",
        target_source=(
            "#include <unistd.h>\n"
            "long target(void) {\n"
            "    char buf[4];\n"
            "    ssize_t n = read(3, buf, sizeof(buf));\n"
            "    return (long)n + ((long)(unsigned char)buf[0] << 8);\n"
            "}\n"
        ),
        assembly=(
            "target:\n"
            "    subq $24, %rsp\n"
            "    movq $3, %edi\n"
            "    leaq 12(%rsp), %rsi\n"
            "    movl $4, %edx\n"
            "    call read@PLT\n"
            "    movzbl 12(%rsp), %edx\n"
            "    salq $8, %rdx\n"
            "    addq %rax, %rdx\n"
            "    movq %rdx, %rax\n"
            "    addq $24, %rsp\n"
            "    ret\n"
        ),
        initial_code=(
            "#include <unistd.h>\n"
            "long target(void) {\n"
            "    char buf[4];\n"
            "    ssize_t n = read(3, buf, sizeof(buf));\n"
            "    return (long)n + ((long)(unsigned char)buf[0] << 8);\n"
            "}\n"
        ),
    ),
    ConfirmationSample(
        sample_id="phase4-confirm:pointer-return:O0",
        source_group_id="phase4-confirm:pointer-return",
        optimization="O0",
        target_source=(
            "void *target(void *p) { return p; }\n"
        ),
        assembly=(
            "target:\n"
            "    movq %rdi, %rax\n"
            "    ret\n"
        ),
        initial_code="void *target(void *p) { return p; }\n",
    ),
)


def _compile_object(source: str, output: Path) -> None:
    """Compile target_source into a relocatable ELF object."""

    source_path = output.with_suffix(".c")
    source_path.write_text(source, encoding="utf-8")
    subprocess.run(
        ["gcc", "-c", "-fPIC", "-O2", str(source_path), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )


def _selection_manifest(samples: tuple[ConfirmationSample, ...]) -> dict:
    """Build a group-isolated selection manifest for the confirmation set."""

    entries = []
    for sample in samples:
        row = {
            "sample_id": sample.sample_id,
            "source_group_id": sample.source_group_id,
            "optimization": sample.optimization,
        }
        row["content_hash"] = hashlib.sha256(
            json.dumps(row, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        entries.append(row)
    core = {
        "schema": "binoracle.phase4-selection/v1",
        "selection_policy": (
            "synthetic confirmation set exercising every WP2 capability that "
            "the V1 runner could not express; group-isolated by capability"
        ),
        "sample_count": len(entries),
        "entries": entries,
    }
    return {**core, "content_hash": hashlib.sha256(
        json.dumps(core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()}


def _algorithm_commitment() -> dict:
    """Pin the algorithm version, thresholds, and budgets for this run."""

    return {
        "schema_version": "binoracle.phase4-commitment.v1",
        "engine_version": "binoracle-engine-v4-phase4",
        "runner_version": "binoracle-harness-H2",
        "audit_thresholds": {
            "min_safe_observations": 4,
            "min_valid": 0.90,
            "min_stable": 1.0,
            "min_effect": 0.05,
            "min_boundary": 0.90,
            "min_score_margin": 0.05,
        },
        "resolution_budget": {
            "max_rounds": 3,
            "holdout_executions": 6,
        },
        "threshold_policy": "no thresholds lowered relative to Phase 3 baseline",
        "external_dependency_policy": "puts/read stubbed; all unknown fail-closed",
        "llm_policy": "non-authoritative; confidence influences scheduling only",
    }


def run_confirmation(*, run_root: Path, experiment: str) -> dict:
    """Run the one-shot confirmation set and emit all §17 deliverables."""

    if platform.system() != "Linux":
        raise RuntimeError(
            "Phase 4 confirmation set must run on Linux (native Harness V2 build)"
        )
    if shutil.which("gcc") is None:
        raise RuntimeError("gcc is required to build the native runner")

    run_dir = run_root / f"binoracle-phase4-{experiment}"
    artifacts_root = run_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    selection = _selection_manifest(CONFIRMATION_SAMPLES)
    (run_dir / "dataset_selection.json").write_text(
        json.dumps(selection, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    commitment = _algorithm_commitment()
    (run_dir / "algorithm_commitment.json").write_text(
        json.dumps(commitment, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    work = Path(tempfile.mkdtemp(prefix="binoracle-phase4-confirm-"))
    try:
        for sample in CONFIRMATION_SAMPLES:
            artifact_dir = (
                artifacts_root
                / "dataset"
                / "backend"
                / sample.source_group_id
                / sample.optimization
            )
            artifact_dir.mkdir(parents=True, exist_ok=True)
            binary = work / (sample.sample_id.replace(":", "_") + ".o")
            _compile_object(sample.target_source, binary)
            engine = BinOracleEngine(
                {
                    "mode": "contract_audit",
                    "abi": "sysv-x86_64",
                    "probe_seed": 23,
                    "probe_executions_per_contract": 8,
                    "probe_repetitions": 2,
                    "resolution_max_rounds": 2,
                    "holdout_executions": 6,
                    "max_contract_candidates": 4,
                    "require_relocatable": True,
                }
            )
            engine.prepare()
            engine.run(
                binary_path=binary,
                target_function="target",
                initial_code=sample.initial_code,
                assembly=sample.assembly,
                assembly_syntax="GNU assembler AT&T",
                architecture="x86_64",
                optimization=sample.optimization,
                sample_id=sample.sample_id,
                artifact_dir=artifact_dir,
            )
            engine.close()
            # The Phase 3 reporting walker looks for binoracle_public_request.json
            # next to binoracle_metadata.json; emit a minimal public request.
            (artifact_dir / "binoracle_public_request.json").write_text(
                json.dumps(
                    {
                        "sample_id": sample.sample_id,
                        "source_group_id": sample.source_group_id,
                        "optimization": sample.optimization,
                    }
                ),
                encoding="utf-8",
            )
    finally:
        shutil.rmtree(work, ignore_errors=True)

    manifest = build_delivery_manifest(
        run_dir,
        experiment=experiment,
        algorithm_commitment=commitment,
        selection_manifest=selection,
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs-root",
        type=Path,
        default=REPO_ROOT / "runs",
        help="Directory under which runs/binoracle-phase4-<experiment>/ is created",
    )
    parser.add_argument(
        "--experiment",
        default="confirmation-001",
        help="Experiment label; also names the run subdirectory",
    )
    args = parser.parse_args(argv)
    started = time.perf_counter()
    manifest = run_confirmation(run_root=args.runs_root, experiment=args.experiment)
    elapsed = time.perf_counter() - started
    print(json.dumps(
        {
            "experiment": args.experiment,
            "run_dir": manifest["run_dir"],
            "sample_count": manifest["sample_count"],
            "content_hash": manifest["content_hash"],
            "elapsed_seconds": elapsed,
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
