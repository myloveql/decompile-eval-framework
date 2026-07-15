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


BUILTINS = {
    "markdown_fence": MarkdownFencePostprocessor,
    "rename_target": RenameTargetPostprocessor,
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

