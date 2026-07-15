from __future__ import annotations

import re
from typing import Any

from .models import CanonicalSample, ProcessedCode
from .util import load_object


class MarkdownFencePostprocessor:
    name = "markdown_fence"

    def process(self, code: str, sample: CanonicalSample, config: dict[str, Any]):
        blocks = re.findall(r"```(?:c|cpp|c\+\+)?\s*\n?(.*?)```", code, flags=re.I | re.S)
        if not blocks:
            return code.strip(), None
        selected = max(blocks, key=len).strip()
        return selected, {"processor": self.name, "blocks_found": len(blocks)}


class RenameTargetPostprocessor:
    name = "rename_target"

    def process(self, code: str, sample: CanonicalSample, config: dict[str, Any]):
        old_name = config.get("from")
        if not old_name:
            pattern = config.get("pattern", r"\b(?:FUN|sub)_[0-9A-Fa-f]+\b")
            match = re.search(pattern + r"\s*\(", code)
            old_name = match.group(0).rsplit("(", 1)[0].strip() if match else None
        if not old_name or old_name == sample.function_name:
            return code, None
        updated, count = re.subn(rf"\b{re.escape(old_name)}\b", sample.function_name, code)
        return updated, {
            "processor": self.name,
            "from": old_name,
            "to": sample.function_name,
            "replacements": count,
        }


class GhidraCompatibilityTypesPostprocessor:
    """Add portable definitions for Ghidra's width-specific unknown scalar types."""

    name = "ghidra_compat_types"
    definitions = {
        "undefined": "typedef unsigned char undefined;",
        "undefined1": "typedef unsigned char undefined1;",
        "undefined2": "typedef unsigned short undefined2;",
        "undefined4": "typedef unsigned int undefined4;",
        "undefined8": "typedef unsigned long long undefined8;",
        "undefined16": "typedef __uint128_t undefined16;",
        "byte": "typedef unsigned char byte;",
    }

    def process(self, code: str, sample: CanonicalSample, config: dict[str, Any]):
        added = [
            declaration for name, declaration in self.definitions.items()
            if re.search(rf"\b{re.escape(name)}\b", code)
            and not re.search(rf"\btypedef\b[^;]*\b{re.escape(name)}\s*;", code)
        ]
        if not added:
            return code, None
        return "\n".join(added) + "\n\n" + code, {
            "processor": self.name,
            "definitions_added": len(added),
            "types": [line.rsplit(" ", 1)[-1].rstrip(";") for line in added],
        }


BUILTINS = {
    "markdown_fence": MarkdownFencePostprocessor,
    "rename_target": RenameTargetPostprocessor,
    "ghidra_compat_types": GhidraCompatibilityTypesPostprocessor,
}


def process_code(raw_output: str, sample: CanonicalSample, configs: list[dict[str, Any] | str]) -> ProcessedCode:
    code = raw_output
    actions: list[dict[str, Any]] = []
    for entry in configs:
        cfg = {"type": entry} if isinstance(entry, str) else dict(entry)
        kind = cfg.pop("type")
        factory = BUILTINS.get(kind) or load_object(kind)
        processor = factory() if isinstance(factory, type) else factory
        code, action = processor.process(code, sample, cfg)
        if action:
            actions.append(action)
    return ProcessedCode(raw_output=raw_output, code=code.strip(), actions=actions)
