"""Real-ELF integration tests for the BinOracle Runner V2 (WP2 / WP3).

These tests build the versioned Harness V2 runtime against small assembly
targets under gcc on Linux and exercise the wire protocol directly. They
satisfy the WP2 exit conditions (six GPR slots, up to three guard-page
protected objects, per-object write sets, fault attribution, pointer return)
and the WP3 exit condition (deterministic ``puts``/``read`` stubs with
unknown dependencies failing closed).

The tests are skipped on non-Linux hosts because the runtime relies on
Linux-specific headers (``sys/mman.h``, ``sys/syscall.h``) and an ELF x86-64
trampoline.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


def _build_runner(stage: Path, target_source: str) -> Path:
    """Compile the V2 runner against a target function body.

    The target source must define ``target`` and must not provide its own
    ``binoracle_target_address``/``binoracle_globals`` symbols.
    """

    runtime = Path(__file__).resolve().parents[1] / "plugins" / "binoracle" / "runtime"
    target = stage / "target.c"
    binding = stage / "binding.c"
    executable = stage / "runner"
    target.write_text(target_source, encoding="utf-8")
    binding.write_text(
        "extern void target(void);\n"
        "void *binoracle_target_address(void) { return (void *)&target; }\n"
        "struct BinOracleGlobal { const char *name; unsigned char *address; unsigned long size; };\n"
        "struct BinOracleGlobal binoracle_globals[1] = {{0, 0, 0}};\n"
        "const unsigned long binoracle_global_count = 0;\n",
        encoding="utf-8",
    )
    command = [
        shutil.which("gcc"), "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fno-pie", "-no-pie", "-I", str(runtime),
        str(runtime / "runner_main.c"), str(runtime / "deterministic_stubs.c"),
        str(runtime / "guard_memory.c"), str(runtime / "observation.c"),
        str(runtime / "abi_trampoline.S"), str(binding), str(target),
        "-o", str(executable),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)
    return executable


def _run(executable: Path, payload: dict) -> dict:
    completed = subprocess.run(
        [str(executable)],
        input=json.dumps(payload),
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


@unittest.skipUnless(platform.system() == "Linux", "BinOracle runner is Linux-only")
class RunnerV2FixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("gcc") is None:
            self.skipTest("gcc is unavailable")
        self.stage = Path(tempfile.mkdtemp(prefix="binoracle-runner-v2-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.stage, ignore_errors=True)

    def test_six_integer_slots_round_trip(self) -> None:
        """All six SysV GPR slots reach the target as integers."""

        target = (
            "long target(long a, long b, long c, long d, long e, long f) {\n"
            "    return a + b*2 + c*3 + d*4 + e*5 + f*6;\n"
            "}\n"
        )
        executable = _build_runner(self.stage, target)
        result = _run(executable, {"gpr": {"RDI": 1, "RSI": 1, "RDX": 1, "RCX": 1, "R8": 1, "R9": 1}})
        self.assertEqual(result["status"], "returned")
        # 1 + 2 + 3 + 4 + 5 + 6 = 21
        self.assertEqual(int(result["return"]["rax"]), 21)

    def test_single_pointer_object_records_write_set(self) -> None:
        """A pointer argument backed by a guarded object reports the write."""

        target = (
            "void target(long *out) { *out = 0xCAFEBABE; }\n"
        )
        executable = _build_runner(self.stage, target)
        payload = {
            "gpr": {"RDI": {"object_ref": "obj0"}},
            "objects": {"obj0": {"size": 8, "bytes_hex": "00" * 8, "placement": "right"}},
        }
        result = _run(executable, payload)
        self.assertEqual(result["status"], "returned")
        obj = result["objects"]["obj0"]
        # After bytes should now contain 0xCAFEBABE in little-endian.
        self.assertEqual(obj["after_hex"], "bebafeca00000000")
        self.assertNotEqual(obj["before_hex"], obj["after_hex"])

    def test_three_independent_objects_each_capture_writes(self) -> None:
        """Three guarded objects survive independently and report writes."""

        target = (
            "void target(long *a, long *b, long *c) { *a = 1; *b = 2; *c = 3; }\n"
        )
        executable = _build_runner(self.stage, target)
        payload = {
            "gpr": {
                "RDI": {"object_ref": "obj0"},
                "RSI": {"object_ref": "obj1"},
                "RDX": {"object_ref": "obj2"},
            },
            "objects": {
                "obj0": {"size": 8, "bytes_hex": "00" * 8, "placement": "right"},
                "obj1": {"size": 8, "bytes_hex": "00" * 8, "placement": "right"},
                "obj2": {"size": 8, "bytes_hex": "00" * 8, "placement": "left"},
            },
        }
        result = _run(executable, payload)
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["objects"]["obj0"]["after_hex"], "0100000000000000")
        self.assertEqual(result["objects"]["obj1"]["after_hex"], "0200000000000000")
        self.assertEqual(result["objects"]["obj2"]["after_hex"], "0300000000000000")

    def test_right_guard_fault_is_attributed(self) -> None:
        """Writing past the right edge faults and is attributed to obj0_guard."""

        # Write an 8-byte value at offset 0 of an 8-byte object, then write
        # 8 bytes at offset 8 - that address falls into the right guard page.
        target = (
            "void target(char *p) {\n"
            "    *(long *)p = 1;\n"
            "    *(long *)(p + 4096) = 2;\n"  # into the right guard
            "}\n"
        )
        executable = _build_runner(self.stage, target)
        payload = {
            "gpr": {"RDI": {"object_ref": "obj0"}},
            "objects": {"obj0": {"size": 8, "bytes_hex": "00" * 8, "placement": "right"}},
        }
        result = _run(executable, payload)
        self.assertEqual(result["status"], "signal")
        self.assertEqual(result["signal"], "SIGSEGV")
        self.assertEqual(result["object"], "obj0")
        self.assertIn(result["fault_address_class"], ("obj0_right_guard", "obj0_payload"))
        # The fault class name must include the object id so we can attribute
        # the crash back to the offending object.
        self.assertTrue(result["fault_address_class"].startswith("obj0_"))

    def test_left_guard_fault_is_attributed(self) -> None:
        """A write before the accessible region faults on the left guard.

        With placement=left the payload starts at the beginning of the
        accessible region, so writing one page below the payload lands in the
        PROT_NONE left guard page and reliably raises SIGSEGV.
        """

        target = (
            "void target(char *p) { *(long *)(p - 4096) = 1; }\n"
        )
        executable = _build_runner(self.stage, target)
        payload = {
            "gpr": {"RDI": {"object_ref": "obj0"}},
            "objects": {"obj0": {"size": 8, "bytes_hex": "00" * 8, "placement": "left"}},
        }
        result = _run(executable, payload)
        self.assertEqual(result["status"], "signal")
        self.assertEqual(result["signal"], "SIGSEGV")
        self.assertEqual(result["object"], "obj0")
        self.assertEqual(result["fault_address_class"], "obj0_left_guard")

    def test_pointer_return_classified_against_known_object(self) -> None:
        """A pointer return inside an object payload is identified with offset."""

        # Return the address of the first byte of the supplied object.
        target = (
            "void *target(void *p) { return p; }\n"
        )
        executable = _build_runner(self.stage, target)
        payload = {
            "gpr": {"RDI": {"object_ref": "obj0"}},
            "objects": {"obj0": {"size": 16, "bytes_hex": "00" * 16, "placement": "right"}},
        }
        result = _run(executable, payload)
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["return"]["object"], "obj0")
        self.assertEqual(int(result["return"]["offset"]), 0)

    def test_pointer_return_outside_known_object_is_uncategorised(self) -> None:
        """A pointer return that escapes every object must be reported as null."""

        target = (
            "void *target(void) { return (void *)0x1234567890ULL; }\n"
        )
        executable = _build_runner(self.stage, target)
        result = _run(executable, {"gpr": {}})
        self.assertEqual(result["status"], "returned")
        self.assertIsNone(result["return"]["object"])
        self.assertIsNone(result["return"]["offset"])

    def test_virtual_read_consumes_only_configured_bytes(self) -> None:
        """The deterministic read stub pulls bytes from virtual_read_bytes.

        When the requested count exceeds the configured stream length the stub
        returns the remaining bytes (here 1 byte for ``"ab"``) rather than
        touching the host fd.
        """

        target = (
            "#include <unistd.h>\n"
            "long target(void) {\n"
            "    char buf[4] = {9, 9, 9, 9};\n"
            "    ssize_t n = read(3, buf, sizeof(buf));\n"
            "    return (long)n + ((long)(unsigned char)buf[0] << 8);\n"
            "}\n"
        )
        executable = _build_runner(self.stage, target)
        result = _run(executable, {"gpr": {}, "virtual_read_bytes": "ab"})
        self.assertEqual(result["status"], "returned")
        # Only one byte was available, so n=1, buf[0]=0xab -> 1 + 0xab00 = 43777.
        self.assertEqual(int(result["return"]["rax"]), 1 + (0xAB << 8))
        events = result["external_events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "read")
        self.assertEqual(events[0]["fd"], 3)
        self.assertEqual(events[0]["requested"], 4)
        self.assertEqual(events[0]["returned"], 1)
        self.assertEqual(events[0]["data_hex"], "ab")

    def test_virtual_read_is_stateful_across_calls(self) -> None:
        """Multiple reads drain virtual_read_bytes in order without host I/O."""

        target = (
            "#include <unistd.h>\n"
            "long target(void) {\n"
            "    char a[2] = {0, 0};\n"
            "    char b[2] = {0, 0};\n"
            "    ssize_t n1 = read(3, a, sizeof(a));\n"
            "    ssize_t n2 = read(3, b, sizeof(b));\n"
            "    return (long)n1 * 1000L + (long)n2 * 100L\n"
            "         + (long)(unsigned char)a[0] * 10L\n"
            "         + (long)(unsigned char)b[0];\n"
            "}\n"
        )
        executable = _build_runner(self.stage, target)
        # virtual_read_bytes = "0102 03" -> first read consumes 0x01 0x02,
        # second read consumes just 0x03 (only one byte remaining).
        result = _run(executable, {"gpr": {}, "virtual_read_bytes": "010203"})
        self.assertEqual(result["status"], "returned")
        # n1=2, n2=1, a[0]=0x01 -> 2*1000 + 1*100 + 1*10 + 3 = 2113
        self.assertEqual(int(result["return"]["rax"]), 2113)
        events = result["external_events"]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["returned"], 2)
        self.assertEqual(events[0]["data_hex"], "0102")
        self.assertEqual(events[1]["returned"], 1)
        self.assertEqual(events[1]["data_hex"], "03")

    def test_puts_event_text_is_bounded_and_captured(self) -> None:
        """puts text is captured as bounded hex without leaking to stdout."""

        target = (
            "#include <stdio.h>\n"
            "int target(void) { puts(\"hello world\"); return 0; }\n"
        )
        executable = _build_runner(self.stage, target)
        result = _run(executable, {"gpr": {}})
        self.assertEqual(result["status"], "returned")
        events = result["external_events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "puts")
        self.assertEqual(events[0]["text_hex"], "68656c6c6f20776f726c64")  # "hello world"
        self.assertFalse(events[0]["text_truncated"])


class UnknownDependencyFailClosedTests(unittest.TestCase):
    """WP3 exit condition: unknown external dependencies must fail closed.

    These checks do not require the Linux runner because the fail-closed
    decision is made by the Python dependency classifier before any candidate
    is linked against the runner.
    """

    def test_unknown_direct_dependency_is_unsupported(self) -> None:
        from plugins.binoracle.dependencies import (
            classify_dependencies,
            unsupported_direct_dependencies,
        )

        deps = classify_dependencies(
            ["socket", "puts", "memcpy"],
            [{"symbol": "socket"}, {"symbol": "puts"}],
        )
        unsupported = unsupported_direct_dependencies(deps)
        # socket is a direct, unknown external and must fail closed.
        self.assertEqual(unsupported, ("socket",))
        classifications = {item["name"]: item for item in deps}
        self.assertFalse(classifications["socket"]["supported"])
        # puts is supplied by the deterministic harness stub.
        self.assertTrue(classifications["puts"]["supported"])
        self.assertEqual(
            classifications["puts"]["classification"],
            "deterministic_harness_stub",
        )
        # memcpy is supplied by whitelisted libc (not the host's unmodelled
        # socket implementation).
        self.assertTrue(classifications["memcpy"]["supported"])

    def test_capability_assessment_rejects_unknown_dependency(self) -> None:
        from plugins.binoracle.capability import assess_capability
        from plugins.binoracle.contract_v2 import ContractGraphV2

        payload = {
            "schema_version": "binoracle.contract.v2",
            "sample_id": "wp3:O0",
            "contract_id": "K-unknown",
            "abi": "sysv-x86_64",
            "arguments": [
                {"slot": 0, "register": "RDI", "kind_candidates": ["integer"], "confidence": 1.0, "evidence_ids": ["i:0"]},
            ],
            "objects": [],
            "return": {"kind_candidates": ["integer"], "observable": True, "confidence": 1.0, "evidence_ids": ["i:1"]},
            "globals": [],
            "dependencies": [{"name": "totally_unknown_symbol"}],
            "unsupported_reasons": [],
            "confidence": 1.0,
            "evidence_ids": ["i:0"],
        }
        report = assess_capability(ContractGraphV2.from_dict(payload))
        self.assertEqual(report.status, "unsupported")
        self.assertTrue(
            any("totally_unknown_symbol" in reason for reason in report.reasons),
            report.reasons,
        )


if __name__ == "__main__":
    unittest.main()
