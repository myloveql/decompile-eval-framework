from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..models import AssemblyInput, BinaryInput, CanonicalSample
from ..util import resolve_path, sha256_json


def sanitize_dependencies(deps: str, *, for_cpp_wrapper: bool) -> str:
    if for_cpp_wrapper:
        deps = re.sub(r"^\s*typedef\s+int\s+bool\s*;.*$", "", deps, flags=re.MULTILINE)
        deps = re.sub(r"^\s*#define\s+(false|true)\s+[01]\s*$", "", deps, flags=re.MULTILINE)
    deps = re.sub(r"/\*<<<\s*orphan\s*\*/", "", deps)
    return re.sub(r"^\s*int\s+printf\s*\([^;]*\)\s*;\s*$", "", deps, flags=re.MULTILINE)


def externalize_target(code: str, function_name: str) -> str:
    match = re.search(rf"\b{re.escape(function_name)}\s*\(", code)
    if not match:
        return code
    prefix = re.sub(r"\b(static|inline|__inline|__inline__|extern)\b", "", code[: match.start()])
    return prefix + code[match.start() :]


class ExeBenchFlatAdapter:
    plugin_name = "exebench_flat"
    default_protocol = "exebench_json_io"

    def __init__(self, config: dict[str, Any], *, base_dir: Path):
        self.config = config
        self.base_dir = base_dir
        self.path = resolve_path(config["path"], base_dir)
        self.dataset_id = config.get("id", "exebench")
        self.split = config.get("split", "benchmark")
        self.assembly_view = config.get("assembly_view", "objdump_intel_instruction_only")
        self.optimizations = set(config.get("optimizations", []))
        self.limit = config.get("limit")
        self.timeout = int(config.get("timeout", 30))
        include_default = base_dir / "third_party" / "exebench" / "exebench"
        self.include_path = resolve_path(config.get("include_path", include_default), base_dir)
        self.evaluation_protocol = None

    def iter_samples(self) -> Iterable[CanonicalSample]:
        rows = json.loads(self.path.read_text(encoding="utf-8"))["samples"]
        emitted = 0
        for row in rows:
            opt = row["optimization"]
            if self.optimizations and opt not in self.optimizations:
                continue
            assembly_record = row.get("assembly", {})
            assembly = assembly_record.get(self.assembly_view, "")
            syntax = assembly_record.get(f"{self.assembly_view}_syntax")
            if not syntax:
                syntax = "Intel" if self.assembly_view.startswith("objdump_intel") else assembly_record.get(
                    "syntax", "GNU assembler AT&T"
                )
            binary_record = row.get("binary") or {}
            binary_path = binary_record.get("path")
            binary = BinaryInput(
                path=str(resolve_path(binary_path, self.base_dir)),
                sha256=binary_record.get("sha256"),
                format=binary_record.get("format", "ELF"),
                architecture=binary_record.get(
                    "architecture", assembly_record.get("architecture", "x86_64")
                ),
            ) if binary_path else None
            yield CanonicalSample(
                dataset_id=self.dataset_id,
                split=self.split,
                sample_id=row["sample_id"],
                source_group_id=row["source_group_id"],
                function_name=row["function_name"],
                language=row.get("source_metadata", {}).get("language", "c"),
                optimization=opt,
                assembly=AssemblyInput(text=assembly, syntax=syntax, view=self.assembly_view),
                content_hash=sha256_json(row),
                binary=binary,
                metadata={
                    "source_type": row.get("source_type"),
                    "signature": row.get("source", {}).get("signature", []),
                    "assembly_origin": assembly_record.get(
                        f"{self.assembly_view}_origin", assembly_record.get("origin")
                    ),
                    "assembly_available": bool(assembly.strip()),
                },
                private_payload={"row": row},
            )
            emitted += 1
            if self.limit is not None and emitted >= int(self.limit):
                break
