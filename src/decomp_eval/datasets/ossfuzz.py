from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Iterable

from ..models import AssemblyInput, BinaryInput, CandidateCompileContext, CanonicalSample
from ..util import resolve_path, sha256_json


class OSSFuzzAdapter:
    """Load DecompileBench's pre-built OSS-Fuzz function dataset."""

    plugin_name = "ossfuzz"
    default_protocol = "ossfuzz_rsr"

    def __init__(self, config: dict[str, Any], *, base_dir: Path):
        self.config = dict(config)
        self.path = resolve_path(config["path"], base_dir)
        self.dataset_id = str(config.get("id", "ossfuzz"))
        self.assembly_view = str(config.get("assembly_view", "objdump_att"))
        self.optimizations = {str(value).lstrip("-") for value in config.get("optimizations", [])}
        self.languages = {str(value).lower() for value in config.get("languages", ["c"])}
        self.limit = config.get("limit")
        self.timeout = int(config.get("timeout", 30))
        self.c_flags = list(config.get("c_flags", ["-std=gnu11", "-w"]))
        self.cpp_flags = list(config.get("cpp_flags", ["-std=gnu++17", "-w"]))
        self.c_libraries = list(config.get("c_libraries", ["-lm"]))
        self.cpp_libraries = list(config.get("cpp_libraries", ["-lm", "-lcrypto"]))
        self.objdump = str(config.get("objdump", "objdump"))
        self.evaluation_protocol = None

    def iter_samples(self) -> Iterable[CanonicalSample]:
        try:
            from datasets import load_from_disk
        except ImportError as error:
            raise RuntimeError("ossfuzz requires the 'datasets' package") from error
        compiled_path = self.path / "compiled_ds"
        if not compiled_path.is_dir():
            raise ValueError(
                f"OSS-Fuzz compiled dataset is missing: {compiled_path}. "
                "Build it with DecompileBench compile_ossfuzz.py first."
            )
        emitted = 0
        for row_number, row in enumerate(load_from_disk(str(compiled_path))):
            opt = str(row.get("opt", "O0")).lstrip("-")
            if self.optimizations and opt not in self.optimizations:
                continue
            language = str(row.get("language", "c")).lower()
            if self.languages and language not in self.languages:
                continue
            binary_path = self.path / str(row.get("path", ""))
            if not binary_path.is_file():
                continue
            function_name = str(row.get("file", ""))
            if not function_name:
                continue
            assembly = self._disassemble(binary_path, function_name)
            if not assembly:
                continue
            project = str(row.get("project", "unknown"))
            sample_id = f"{self.dataset_id}:{project}:{function_name}:{opt}"
            cpp = language in {"cpp", "c++", "cxx"}
            yield CanonicalSample(
                dataset_id=self.dataset_id,
                split="benchmark",
                sample_id=sample_id,
                source_group_id=f"{self.dataset_id}:{project}:{function_name}",
                function_name=function_name,
                language=language,
                optimization=opt,
                assembly=AssemblyInput(text=assembly, syntax="att", view=self.assembly_view),
                content_hash=sha256_json(dict(row)),
                binary=BinaryInput(path=str(binary_path), format="elf", architecture="x86_64"),
                compile_context=CandidateCompileContext(
                    language=language,
                    compiler="clang++" if cpp else "clang",
                    flags=tuple(self.cpp_flags if cpp else self.c_flags),
                    libraries=tuple(self.cpp_libraries if cpp else self.c_libraries),
                    prelude=str(row.get("include", "")),
                ),
                metadata={
                    "project": project,
                    "source_path": str(binary_path),
                    "function_address": row.get("addr"),
                    "assembly_available": True,
                },
                private_payload={"row": dict(row)},
            )
            emitted += 1
            if self.limit is not None and emitted >= int(self.limit):
                return

    def _disassemble(self, binary_path: Path, function_name: str) -> str:
        try:
            completed = subprocess.run(
                [self.objdump, "-d", f"--disassemble={function_name}", str(binary_path)],
                capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return completed.stdout if completed.returncode == 0 else ""
