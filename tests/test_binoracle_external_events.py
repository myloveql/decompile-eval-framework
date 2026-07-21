from __future__ import annotations

import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(platform.system() == "Linux", "BinOracle runner is Linux-only")
class ExternalStubEventTests(unittest.TestCase):
    def test_runner_records_bounded_puts_and_read_events(self):
        compiler = shutil.which("gcc")
        if compiler is None:
            self.skipTest("gcc is unavailable")
        root = Path(__file__).resolve().parents[1]
        runtime = root / "plugins" / "binoracle" / "runtime"
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            target = stage / "target.c"
            binding = stage / "binding.c"
            executable = stage / "runner"
            target.write_text(
                "#include <unistd.h>\n"
                "#include <stdio.h>\n"
                "void target(void) {\n"
                "    char data[300];\n"
                "    puts(\"hello\");\n"
                "    ssize_t n = read(7, data, sizeof(data));\n"
                "    (void)n;\n"
                "}\n",
                encoding="utf-8",
            )
            binding.write_text(
                "extern void target(void);\n"
                "void *binoracle_target_address(void) { return (void *)&target; }\n"
                "struct BinOracleGlobal { const char *name; unsigned char *address; unsigned long size; };\n"
                "struct BinOracleGlobal binoracle_globals[1] = {{0, 0, 0}};\n"
                "const unsigned long binoracle_global_count = 0;\n",
                encoding="utf-8",
            )
            command = [
                compiler, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-fno-pie", "-no-pie", "-I", str(runtime),
                str(runtime / "runner_main.c"), str(runtime / "deterministic_stubs.c"),
                str(runtime / "guard_memory.c"), str(runtime / "observation.c"),
                str(runtime / "abi_trampoline.S"), str(binding), str(target),
                "-o", str(executable),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            completed = subprocess.run(
                [str(executable)],
                input=json.dumps({"gpr": {}, "objects": {}, "virtual_read_bytes": "0102"}),
                check=True,
                capture_output=True,
                text=True,
            )
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "returned")
        self.assertEqual(
            result["external_events"],
            [
                {
                    "kind": "puts", "sequence": 1, "text_hex": "68656c6c6f",
                    "text_truncated": False,
                },
                {
                    "kind": "read", "sequence": 2, "fd": 7, "requested": 300,
                    "returned": 2, "data_hex": "0102", "data_truncated": False,
                },
            ],
        )
        self.assertFalse(result["external_events_truncated"])


if __name__ == "__main__":
    unittest.main()
