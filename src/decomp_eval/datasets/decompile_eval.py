from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ..models import AssemblyInput, CanonicalSample, PseudocodeInput
from ..util import resolve_path, sha256_json, sha256_text


class DecompileEvalAdapter:
    plugin_name = "decompile_eval"
    default_protocol = "decompile_eval_exitcode"
    allowed_splits = {"humaneval", "mbpp"}

    def __init__(self, config: dict[str, Any], *, base_dir: Path):
        self.config = config
        self.path = resolve_path(config["path"], base_dir)
        self.dataset_id = config.get("id", "decompile-eval")
        self.splits = config.get("splits", ["humaneval", "mbpp"])
        unsupported = set(self.splits) - self.allowed_splits
        if unsupported:
            raise ValueError(f"Unsupported or intentionally excluded splits: {sorted(unsupported)}")
        self.assembly_view = config.get("assembly_view", "asm")
        self.pseudocode_view = config.get("pseudocode_view")
        self.optimizations = set(config.get("optimizations", []))
        self.languages = set(config.get("languages", []))
        self.limit = config.get("limit")
        self.timeout = int(config.get("timeout", 30))
        self.c_flags = list(config.get("c_flags", ["-std=gnu11", "-w"]))
        self.cpp_flags = list(config.get("cpp_flags", ["-std=gnu++17", "-w"]))
        self.c_libraries = list(config.get("c_libraries", ["-lm"]))
        self.cpp_libraries = list(config.get("cpp_libraries", ["-lm", "-lcrypto"]))
        self.evaluation_protocol = None

    def iter_samples(self) -> Iterable[CanonicalSample]:
        try:
            from datasets import load_from_disk
        except ImportError as error:
            raise RuntimeError("decompile-eval requires the 'datasets' package") from error
        emitted = 0
        for split in self.splits:
            dataset = load_from_disk(str(self.path / split))
            for row_number, row in enumerate(dataset):
                opt = str(row.get("opt", "O0")).lstrip("-")
                language = str(row.get("language", "c")).lower()
                if self.optimizations and opt not in self.optimizations:
                    continue
                if self.languages and language not in self.languages:
                    continue
                assembly = row.get(self.assembly_view, "") or ""
                pseudocode_text = (
                    row.get(self.pseudocode_view, "") or "" if self.pseudocode_view else ""
                )
                pseudocode = PseudocodeInput(
                    text=pseudocode_text,
                    view=self.pseudocode_view,
                    producer=self.pseudocode_view.removesuffix("_pseudo"),
                    sha256=sha256_text(pseudocode_text),
                ) if pseudocode_text else None
                index = str(row.get("index", row_number))
                yield CanonicalSample(
                    dataset_id=self.dataset_id,
                    split=split,
                    sample_id=f"{self.dataset_id}:{split}:{index}:{opt}",
                    source_group_id=f"{self.dataset_id}:{split}:{index}",
                    function_name=str(row["func_name"]),
                    language=language,
                    optimization=opt,
                    assembly=AssemblyInput(text=assembly, syntax=self._syntax(), view=self.assembly_view),
                    content_hash=sha256_json(row),
                    pseudocode=pseudocode,
                    metadata={
                        "index": row.get("index"),
                        "available_assembly_views": ["asm", "ida_asm", "ghidra_asm"],
                        "available_pseudocode_views": ["ida_pseudo", "ghidra_pseudo"],
                        "assembly_available": bool(assembly.strip()),
                    },
                    private_payload={"row": dict(row)},
                )
                emitted += 1
                if self.limit is not None and emitted >= int(self.limit):
                    return

    def _syntax(self) -> str:
        return "intel" if self.assembly_view in {"ida_asm", "ghidra_asm"} else "att"
