from __future__ import annotations

import json
import re
import struct
import time
from pathlib import Path
from typing import Any

from decomp_eval.models import DecompileRequest, DecompileResult
from plugins.openai_compatible_backend import extract_candidate_code

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "parse_data",
            "description": "Parse data from a label in preprocessed assembly using a guessed data type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "data_label": {"type": "string"},
                    "data_type": {"type": "string"},
                },
                "required": ["data_label", "data_type"],
                "additionalProperties": False,
            },
        },
    }
]

STRUCT_MAPPING = {
    "i8": ("b", 1), "u8": ("B", 1), "i16": ("h", 2), "u16": ("H", 2),
    "i32": ("i", 4), "u32": ("I", 4), "i64": ("q", 8), "u64": ("Q", 8),
    "f32": ("f", 4), "f64": ("d", 8), "byte": ("B", 1), "word": ("H", 2),
    "dword": ("I", 4), "qword": ("Q", 8),
}


class ReFDecBackend:
    """ReF-Dec assembly-to-C backend with one data-tool follow-up round."""

    version = "refdec-adapter-v1"

    def __init__(self, config: dict[str, Any], **_: Any):
        self.config = dict(config)
        self.model = str(config.get("model", "refdec"))
        self.base_url = str(config.get("base_url", "http://127.0.0.1:8000/v1"))
        self.api_key = str(config.get("api_key", "not-required"))
        self.api_key_env = str(config.get("api_key_env", "REFDEC_API_KEY"))
        self.temperature = float(config.get("temperature", 0.0))
        self.max_tokens = int(config.get("max_tokens", 2048))
        self.timeout = float(config.get("timeout", 300))
        self.max_retries = max(0, int(config.get("max_retries", 3)))
        self.enable_tool = bool(config.get("enable_tool", True))
        self.client: Any = None
        self.version = f"{type(self).version}:{self.model}:tool={self.enable_tool}"

    def prepare(self, requests: list[DecompileRequest]) -> None:
        try:
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError("ReF-Dec requires OpenAI; install with: pip install -e '.[refdec]'") from error
        import os
        key = os.environ.get(self.api_key_env, self.api_key)
        self.client = OpenAI(api_key=key or "not-required", base_url=self.base_url,
                             timeout=self.timeout, max_retries=self.max_retries)

    @staticmethod
    def _tool_result(rodata: dict[str, Any], label: str, data_type: str) -> str:
        mapping = rodata.get("address_mapping", {})
        entry = mapping.get(label)
        if not entry:
            return f"Not Found {label}!"
        type_name = data_type.lower().strip()
        match = re.fullmatch(r"(i8|u8|i16|u16|i32|u32|i64|u64|f32|f64|byte|word|dword|qword)(?:\[(\d+)\])?", type_name)
        if not match:
            return f"Read {label} failed!"
        fmt, size = STRUCT_MAPPING[match.group(1)]
        count = int(match.group(2) or 1)
        try:
            raw = bytes.fromhex(str(rodata.get("rodata_data", "")))
            offset = int(entry.get("addr", 0)) - int(rodata.get("rodata_addr", 0))
            values = struct.unpack("<" + fmt * count, raw[offset:offset + size * count])
            return json.dumps(values[0] if count == 1 else values)
        except Exception:
            return f"Read {label} failed!"

    def _request(self, messages: list[dict[str, Any]], with_tools: bool):
        params: dict[str, Any] = {
            "model": self.model, "messages": messages, "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if with_tools:
            params["tools"] = TOOLS
        return self.client.chat.completions.create(**params)

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if self.client is None:
            self.prepare([request])
        asm = request.assembly.text.strip()
        if not asm:
            return DecompileResult(False, reason="refdec_missing_assembly", backend_version=self.version,
                                   elapsed_seconds=time.perf_counter() - started)
        rodata = request.metadata.get("refdec_rodata", {})
        prompt = "What is the c source code of the assembly code below:\n\n" + asm
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        records: list[dict[str, Any]] = []
        try:
            response = self._request(messages, self.enable_tool)
            message = response.choices[0].message
            tool_calls = list(getattr(message, "tool_calls", None) or [])
            if tool_calls:
                messages.append({"role": "assistant", "content": message.content, "tool_calls": [
                    {"id": call.id, "type": "function", "function": {
                        "name": call.function.name, "arguments": call.function.arguments}}
                    for call in tool_calls
                ]})
                for call in tool_calls:
                    args = json.loads(call.function.arguments)
                    value = self._tool_result(rodata, str(args.get("data_label", "")), str(args.get("data_type", "")))
                    records.append({"arguments": args, "result": value})
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": value})
                response = self._request(messages, self.enable_tool)
            raw = str(response.choices[0].message.content or "")
            candidate, policy = extract_candidate_code(raw)
            (artifact_dir / "refdec_prompt.txt").write_text(prompt, encoding="utf-8")
            (artifact_dir / "refdec_response.txt").write_text(raw, encoding="utf-8")
            (artifact_dir / "refdec_metadata.json").write_text(json.dumps({
                "model": self.model, "enable_tool": self.enable_tool,
                "tool_calls": records, "candidate_extraction_policy": policy,
                "backend_version": self.version,
            }, indent=2) + "\n", encoding="utf-8")
            if not candidate.strip():
                return DecompileResult(False, raw_output=raw, reason="refdec_empty_output",
                                       elapsed_seconds=time.perf_counter() - started, backend_version=self.version)
            return DecompileResult(True, raw_output=raw, code=candidate,
                                   elapsed_seconds=time.perf_counter() - started, backend_version=self.version)
        except Exception as error:
            (artifact_dir / "refdec_metadata.json").write_text(json.dumps({
                "error_type": type(error).__name__, "error": repr(error),
                "tool_calls": records, "backend_version": self.version,
            }, indent=2) + "\n", encoding="utf-8")
            return DecompileResult(False, reason="refdec_pipeline_failed", log=repr(error),
                                   elapsed_seconds=time.perf_counter() - started, backend_version=self.version)

    def close(self) -> None:
        self.client = None
