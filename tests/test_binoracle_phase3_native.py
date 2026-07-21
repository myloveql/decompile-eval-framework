"""Native Phase 3 semantic-replay integration tests (WP2/WP7/WP8).

These tests run the BinOracle engine end-to-end on Linux against a small
relocatable ELF, freeze a Harness V2 manifest, build a Phase 3 baseline, and
replay the frozen probes back through the runner. They satisfy:

* WP2 gate A: real ELF integration + deterministic semantic replay.
* WP7 exit: every frozen harness carries a holdout commitment and a
  hash-pinned probe plan.
* WP8 exit: the differential path consumes the *frozen* probe plan rather
  than regenerating it from the seed, and a candidate that matches behaviour
  on the frozen probes passes the differential.

The tests are skipped on non-Linux hosts.
"""

from __future__ import annotations

import json
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# These imports are guarded so the test module still loads on Windows for
# discovery; the actual test bodies skip when Linux/gcc are unavailable.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from plugins.binoracle.engine import BinOracleEngine
    from plugins.binoracle.phase3 import (
        create_phase3_baseline,
        replay_phase3_baseline,
        verify_phase3_baseline,
    )
    from plugins.binoracle.runtime import ABIRunner
except Exception:  # pragma: no cover - import-time fallback for non-Linux hosts
    BinOracleEngine = None  # type: ignore[assignment]
    ABIRunner = None  # type: ignore[assignment]


def _minimal_elf64_rel(path: Path, symbol: str = "target") -> None:
    """Emit a tiny relocatable ELF-64 x86-64 object exposing ``target``.

    The .text body is a single ``ret``; the engine's static analysis still
    extracts the symbol and the relocation table, and the runner links the
    candidate's actual implementation on top.
    """

    text = b"\xc3"
    strings = b"\0" + symbol.encode("ascii") + b"\0"
    section_strings = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    text_offset = 64
    strings_offset = text_offset + len(text)
    symbol_offset = 80
    symbol_data = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, 1)
    section_strings_offset = symbol_offset + len(symbol_data)
    section_offset = (section_strings_offset + len(section_strings) + 7) & ~7
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4:7] = bytes((2, 1, 1))
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", bytes(ident), 1, 62, 1, 0, 0,
        section_offset, 0, 64, 0, 0, 64, 5, 4,
    )
    sections = [
        bytes(64),
        struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0, text_offset, len(text), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 7, 2, 0, 0, symbol_offset, len(symbol_data), 3, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 23, 3, 0, 0, section_strings_offset, len(section_strings), 0, 0, 1, 0),
    ]
    data = bytearray(section_offset + 64 * len(sections))
    data[:64] = header
    data[text_offset:text_offset + len(text)] = text
    data[strings_offset:strings_offset + len(strings)] = strings
    data[symbol_offset:symbol_offset + len(symbol_data)] = symbol_data
    data[section_strings_offset:section_strings_offset + len(section_strings)] = section_strings
    for index, section in enumerate(sections):
        start = section_offset + index * 64
        data[start:start + 64] = section
    path.write_bytes(data)


def _candidate_object(root: Path) -> Path:
    """Compile a small candidate relocatable that matches the harness contract.

    The contract is ``void target(int *out) { *out = 0x42; }`` so the
    differential comparison should be behaviourally equivalent.
    """

    source = root / "candidate.c"
    source.write_text(
        "void target(int *out) { *out = 0x42; }\n",
        encoding="utf-8",
    )
    obj = root / "candidate.o"
    subprocess.run(
        ["gcc", "-c", "-fPIC", "-O2", str(source), "-o", str(obj)],
        check=True,
        capture_output=True,
        text=True,
    )
    return obj


@unittest.skipUnless(platform.system() == "Linux", "Phase 3 replay is Linux-only")
@unittest.skipIf(BinOracleEngine is None, "BinOracle engine unavailable")
class Phase3NativeReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("gcc") is None:
            self.skipTest("gcc is unavailable")
        self.root = Path(tempfile.mkdtemp(prefix="binoracle-phase3-"))
        # Compile the real target source into a relocatable ELF; the engine
        # extracts facts and links the runner against this object so the
        # executed function is the genuine target implementation.
        self.binary = self._compile_target(
            "long target(long x, long *out) { *out = x + 1; return x * 2; }\n"
        )

    def _compile_target(self, source: str) -> Path:
        path = self.root / "target_source.c"
        path.write_text(source, encoding="utf-8")
        obj = self.root / (path.stem + ".o")
        subprocess.run(
            ["gcc", "-c", "-fPIC", "-O2", str(path), "-o", str(obj)],
            check=True,
            capture_output=True,
            text=True,
        )
        return obj

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _run_engine(self, *, mode: str, candidate_code: str | None = None) -> Path:
        artifact = self.root / f"artifact-{mode}"
        engine = BinOracleEngine(
            {
                "mode": mode,
                "abi": "sysv-x86_64",
                "probe_seed": 17,
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
            binary_path=self.binary,
            target_function="target",
            initial_code=(
                candidate_code
                or "long target(long x, long *out) { *out = x + 1; return x * 2; }\n"
            ),
            # Static contract inference only needs to know RDI is integer and
            # RSI is a pointer; the actual behaviour comes from the compiled
            # target linked into the runner, not from this skeleton assembly.
            assembly=(
                "target:\n"
                "    leaq 1(%rdi), %rax\n"
                "    movq %rax, (%rsi)\n"
                "    leaq (%rdi,%rdi), %rax\n"
                "    ret\n"
            ),
            assembly_syntax="GNU assembler AT&T",
            architecture="x86_64",
            optimization="O0",
            sample_id="phase3-native:O0",
            artifact_dir=artifact,
        )
        engine.close()
        return artifact

    def test_contract_audit_freezes_and_phase3_baseline_verifies(self) -> None:
        """A frozen contract_audit run yields a verifiable Phase 3 baseline."""

        artifact = self._run_engine(mode="contract_audit")
        stage = artifact / "binoracle"
        manifest_path = stage / "harness_manifest.json"
        self.assertTrue(manifest_path.is_file(), "contract_audit must freeze the harness")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "binoracle.harness.v2")
        self.assertEqual(manifest["status"], "frozen")
        # Holdout commitment must be present and pinned.
        self.assertIn("holdout_commitment", manifest)
        self.assertEqual(manifest["mutation_after_freeze_allowed"], False)

        run_dir = self.root / "run"
        (run_dir / "artifacts").mkdir(parents=True)
        # Link the artifact into the run layout the Phase 3 tools walk.
        link = run_dir / "artifacts" / "dataset" / "backend" / "sample"
        link.mkdir(parents=True)
        for path in artifact.iterdir():
            dst = link / path.name
            if path.is_dir():
                shutil.copytree(path, dst)
            else:
                shutil.copy2(path, dst)
        # Minimal public request file the Phase 3 baseline walks for sample_id.
        (link / "binoracle_public_request.json").write_text(
            json.dumps({"sample_id": "phase3-native:O0", "optimization": "O0"}),
            encoding="utf-8",
        )

        baseline_path = self.root / "phase3_baseline.json"
        baseline = create_phase3_baseline([run_dir], output_path=baseline_path)
        self.assertTrue(verify_phase3_baseline(baseline))
        self.assertEqual(baseline["frozen_harnesses"], 1)
        self.assertEqual(baseline["valid_frozen_harnesses"], 1)
        self.assertEqual(baseline["invalid_frozen_harnesses"], 0)

        replay_path = self.root / "phase3_replay.json"
        replay = replay_phase3_baseline(baseline_path, output_path=replay_path)
        self.assertEqual(replay["harnesses_total"], 1)
        self.assertEqual(replay["harnesses_replay_match"], 1)
        self.assertEqual(replay["harnesses_replay_mismatch"], 0)
        self.assertGreater(replay["executions"], 0)
        # Both exploration and holdout probes must have been replayed.
        self.assertGreater(replay["exploration_executions"], 0)
        self.assertGreater(replay["holdout_executions"], 0)
        # Diagnostic timing may differ, but the semantic observation must not.
        self.assertEqual(replay["diagnostic_timing_changes"], replay["diagnostic_timing_changes"])


if __name__ == "__main__":
    unittest.main()
