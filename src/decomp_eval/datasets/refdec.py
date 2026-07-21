from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..models import AssemblyInput, CandidateCompileContext, CanonicalSample, OracleContext
from ..util import resolve_path, sha256_json

_INCLUDE_RE = re.compile(r"^\s*#\s*include\s+[^\n]+\n?", re.MULTILINE)


class ReFDecAdapter:
    """Adapter for ReF-Dec's labeled x86-64 assembly and .rodata dataset."""

    plugin_name = "refdec"
    default_protocol = "decompile_eval_exitcode"

    def __init__(self, config: dict[str, Any], *, base_dir: Path):
        self.config = dict(config)
        self.path = resolve_path(config["path"], base_dir)
        self.dataset_id = str(config.get("id", "refdec"))
        self.optimizations = {str(value).lstrip("-") for value in config.get("optimizations", [])}
        self.limit = config.get("limit")
        self.timeout = int(config.get("timeout", 30))
        self.c_flags = list(config.get("c_flags", ["-std=gnu11", "-w"]))
        self.c_libraries = list(config.get("c_libraries", ["-lm"]))
        self.cpp_flags = list(config.get("cpp_flags", ["-std=gnu++17", "-w"]))
        self.cpp_libraries = list(config.get("cpp_libraries", ["-lm", "-lcrypto"]))
        self.evaluation_protocol = None

    def iter_samples(self) -> Iterable[CanonicalSample]:
        if not self.path.is_file():
            raise ValueError(f"ReF-Dec dataset JSON is missing: {self.path}")
        rows = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise ValueError(f"ReF-Dec dataset must be a JSON array: {self.path}")
        emitted = 0
        for row_number, row in enumerate(rows):
            opt = str(row.get("type", "O0")).lstrip("-")
            if self.optimizations and opt not in self.optimizations:
                continue
            source = str(row.get("c_func", ""))
            assembly = str(row.get("asm_labeled", ""))
            if not source or not assembly:
                continue
            task_id = str(row.get("task_id", row_number))
            includes = "\n".join(_INCLUDE_RE.findall(source)).strip()
            function = _INCLUDE_RE.sub("", source).strip()
            name = self._function_name(function, f"func{task_id}")
            normalized = {"func": function, "func_dep": includes, "test": str(row.get("c_test", ""))}
            yield CanonicalSample(
                dataset_id=self.dataset_id,
                split="benchmark",
                sample_id=f"{self.dataset_id}:benchmark:{task_id}:{opt}",
                source_group_id=f"{self.dataset_id}:benchmark:{task_id}",
                function_name=name,
                language="c",
                optimization=opt,
                assembly=AssemblyInput(text=assembly, syntax="att", view="refdec_labeled_asm"),
                content_hash=sha256_json(row),
                compile_context=CandidateCompileContext(
                    language="c", compiler="gcc", flags=tuple(self.c_flags),
                    libraries=tuple(self.c_libraries), prelude=includes,
                ),
                oracle_context=OracleContext(
                    protocol="decompile_eval_exitcode",
                    payload={"test": normalized["test"], "feedback_policy": "exitcode_only"},
                ),
                metadata={
                    "task_id": row.get("task_id", row_number),
                    "assembly_available": bool(assembly.strip()),
                    "refdec_rodata": {
                        "address_mapping": dict(row.get("address_mapping", {})),
                        "rodata_addr": int(row.get("rodata_addr") or 0),
                        "rodata_data": str(row.get("rodata_data", "")),
                    },
                },
                private_payload={"row": normalized, "refdec_row": dict(row)},
            )
            emitted += 1
            if self.limit is not None and emitted >= int(self.limit):
                return

    @staticmethod
    def _function_name(source: str, fallback: str) -> str:
        match = re.search(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", source)
        return match.group(1) if match else fallback
