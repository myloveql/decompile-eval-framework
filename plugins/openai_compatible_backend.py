from __future__ import annotations

import copy
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from decomp_eval.backends.base import BaseBackend
from decomp_eval.models import DecompileRequest, DecompileResult


_FENCE_RE = re.compile(
    r"```[ \t]*(?P<language>[^\n`]*)\r?\n(?P<code>.*?)```",
    re.DOTALL,
)
_C_LANGUAGES = {"c", "c99", "c11", "cpp", "c++", "cc", "cxx"}


def extract_candidate_code(text: str) -> tuple[str, str]:
    """Extract the most likely C/C++ translation unit while preserving raw model text."""
    source = text.strip()
    if not source:
        return "", "empty"
    fences = [
        (match.group("language").strip().lower(), match.group("code").strip())
        for match in _FENCE_RE.finditer(source)
        if match.group("code").strip()
    ]
    c_fences = [code for language, code in fences if language in _C_LANGUAGES]
    if c_fences:
        return max(c_fences, key=len), "longest_c_fence"
    if fences:
        return max((code for _, code in fences), key=len), "longest_fence"
    return source, "full_response"


class _PromptValues(dict[str, str]):
    def __missing__(self, key: str) -> str:
        raise ValueError(f"Unknown user_prompt_template placeholder: {{{key}}}")


class OpenAICompatibleBackend(BaseBackend):
    """Closed-model backend using the OpenAI Python SDK and compatible HTTP APIs."""

    DEFAULT_SYSTEM_PROMPT = (
        "You are an expert binary decompiler. Reconstruct the requested function as complete, "
        "compilable C or C++ source code. Preserve behavior and the target function signature. "
        "Return only source code, preferably in one C/C++ Markdown code fence."
    )

    def __init__(self, config: dict[str, Any], **_: Any):
        self.config = dict(config)
        self.backend_id = str(config.get("id", "openai-compatible"))
        self.provider = str(config.get("provider", "openai"))
        self.model = str(config.get("model", "")).strip()
        if not self.model:
            raise ValueError(f"Decompiler {self.backend_id}: model is required")
        self.api_mode = str(config.get("api_mode", "responses"))
        if self.api_mode not in {"responses", "chat_completions"}:
            raise ValueError("api_mode must be responses or chat_completions")
        self.base_url = config.get("base_url")
        if self.provider != "openai" and not self.base_url:
            raise ValueError(
                f"Decompiler {self.backend_id}: base_url is required for provider {self.provider!r}"
            )
        self.system_prompt = str(config.get("system_prompt", self.DEFAULT_SYSTEM_PROMPT))
        self.user_prompt_template = config.get("user_prompt_template")
        self.temperature = config.get("temperature")
        self.max_output_tokens = int(config.get("max_output_tokens", 4096))
        self.max_concurrency = max(1, int(config.get("max_concurrency", 1)))
        self.timeout = float(config.get("timeout", 120))
        self.max_retries = max(0, int(config.get("max_retries", 3)))
        self.empty_output_retries = max(0, int(config.get("empty_output_retries", 2)))
        self.empty_output_backoff_seconds = max(
            0.0, float(config.get("empty_output_backoff_seconds", 1.0))
        )
        self.empty_output_backoff_max_seconds = max(
            self.empty_output_backoff_seconds,
            float(config.get("empty_output_backoff_max_seconds", 8.0)),
        )
        self.thinking_mode = str(config.get("thinking_mode", "auto")).strip().lower()
        if self.thinking_mode not in {"auto", "enabled", "disabled"}:
            raise ValueError("thinking_mode must be auto, enabled, or disabled")
        self.thinking_protocol = self._resolve_thinking_protocol(
            str(config.get("thinking_protocol", "auto")).strip().lower()
        )
        self.extra_body = self._build_extra_body(config.get("extra_body", {}))
        self._validate_thinking_mode()
        self.version = str(config.get("version", f"{self.provider}:{self.model}"))
        self._client: Any = None

    def _resolve_thinking_protocol(self, configured: str) -> str:
        if configured not in {"auto", "thinking_type", "custom"}:
            raise ValueError("thinking_protocol must be auto, thinking_type, or custom")
        if configured != "auto":
            return configured
        provider = self.provider.strip().lower()
        if provider in {"kimi", "moonshot", "moonshotai"}:
            return "thinking_type"
        if provider in {"zhipu", "zhipuai", "bigmodel"}:
            return "thinking_type"
        return "none"

    @classmethod
    def _merge_payload(
        cls, target: dict[str, Any], payload: dict[str, Any], path: str = ""
    ) -> None:
        for key, value in payload.items():
            field = f"{path}.{key}" if path else key
            if key not in target:
                target[key] = value
            elif isinstance(target[key], dict) and isinstance(value, dict):
                cls._merge_payload(target[key], value, field)
            elif target[key] != value:
                raise ValueError(f"thinking payload conflicts with extra_body.{field}")

    def _build_extra_body(self, configured: Any) -> dict[str, Any]:
        extra_body = copy.deepcopy(dict(configured or {}))
        if self.thinking_mode == "auto":
            return extra_body
        if self.thinking_protocol == "thinking_type":
            payload = {"thinking": {"type": self.thinking_mode}}
        elif self.thinking_protocol == "custom":
            payload = copy.deepcopy(self.config.get("thinking_payload"))
            if not isinstance(payload, dict) or not payload:
                raise ValueError(
                    "thinking_protocol: custom requires a non-empty thinking_payload object"
                )
        else:
            raise ValueError(
                f"Provider {self.provider!r} has no built-in thinking protocol; set "
                "thinking_protocol and, when custom, thinking_payload explicitly"
            )
        self._merge_payload(extra_body, payload)
        return extra_body

    def _validate_thinking_mode(self) -> None:
        provider = self.provider.strip().lower()
        model = self.model.lower()
        is_kimi = provider in {"kimi", "moonshot", "moonshotai"}
        if is_kimi and model.startswith("kimi-k2.7-code") and self.thinking_mode != "auto":
            raise ValueError(
                f"Model {self.model!r} is always-thinking and must use thinking_mode: auto; "
                "Kimi rejects disabled and recommends omitting the thinking parameter for this model"
            )

    def _resolve_api_key(self) -> str:
        configured = self.config.get("api_key")
        if configured:
            value = str(configured)
            if value.startswith("env:"):
                variable = value[4:]
                key = os.environ.get(variable)
                if not key:
                    raise RuntimeError(f"API key environment variable {variable!r} is not set")
                return key
            match = re.fullmatch(r"\$\{([^}]+)}", value)
            if match:
                variable = match.group(1)
                key = os.environ.get(variable)
                if not key:
                    raise RuntimeError(f"API key environment variable {variable!r} is not set")
                return key
            return value
        variable = str(self.config.get("api_key_env", "OPENAI_API_KEY"))
        key = os.environ.get(variable)
        if not key:
            raise RuntimeError(
                f"Decompiler {self.backend_id}: API key environment variable {variable!r} is not set"
            )
        return key

    def prepare(self, requests: list[DecompileRequest]) -> None:
        try:
            from openai import OpenAI
        except ImportError as error:
            raise RuntimeError(
                "The openai package is required; install the project with: pip install -e '.[api]'"
            ) from error
        options: dict[str, Any] = {
            "api_key": self._resolve_api_key(),
            "timeout": self.timeout,
            "max_retries": self.max_retries,
        }
        if self.base_url:
            options["base_url"] = str(self.base_url)
        self._client = OpenAI(**options)

    def _build_prompt(self, request: DecompileRequest) -> str:
        values = _PromptValues(
            dataset_id=request.dataset_id,
            split=request.split,
            sample_id=request.sample_id,
            source_group_id=request.source_group_id,
            function_name=request.function_name,
            language=request.language,
            optimization=request.optimization,
            assembly=request.assembly.text,
            assembly_syntax=request.assembly.syntax,
            assembly_view=request.assembly.view,
            pseudocode=request.pseudocode.text if request.pseudocode else "",
            pseudocode_view=request.pseudocode.view if request.pseudocode else "",
            pseudocode_producer=request.pseudocode.producer if request.pseudocode else "",
        )
        if self.user_prompt_template is not None:
            return str(self.user_prompt_template).format_map(values)
        sections = [
            f"Target function: {request.function_name}",
            f"Language: {request.language}",
            f"Compiler optimization: {request.optimization}",
        ]
        if request.assembly.text.strip():
            sections.append(
                f"Assembly ({request.assembly.syntax}, view={request.assembly.view}):\n"
                f"```asm\n{request.assembly.text.strip()}\n```"
            )
        if request.pseudocode and request.pseudocode.text.strip():
            sections.append(
                f"Existing pseudocode (producer={request.pseudocode.producer}, "
                f"view={request.pseudocode.view}):\n"
                f"```c\n{request.pseudocode.text.strip()}\n```"
            )
        sections.append("Produce the reconstructed source code now.")
        return "\n\n".join(sections)

    @staticmethod
    def _serializable(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool, list, dict)):
            return value
        if hasattr(value, "model_dump"):
            return value.model_dump()
        return str(value)

    def _infer(self, prompt: str) -> tuple[str, dict[str, Any]]:
        if self._client is None:
            raise RuntimeError("Backend is not prepared")
        if self.api_mode == "responses":
            params: dict[str, Any] = {
                "model": self.model,
                "instructions": self.system_prompt,
                "input": prompt,
                "max_output_tokens": self.max_output_tokens,
            }
            if self.temperature is not None:
                params["temperature"] = self.temperature
            if self.extra_body:
                params["extra_body"] = self.extra_body
            response = self._client.responses.create(**params)
            text = str(getattr(response, "output_text", "") or "")
            metadata = {
                "request_id": getattr(response, "id", None),
                "status": getattr(response, "status", None),
                "usage": self._serializable(getattr(response, "usage", None)),
            }
            return text, metadata

        params = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self.max_output_tokens,
        }
        if self.temperature is not None:
            params["temperature"] = self.temperature
        if self.extra_body:
            params["extra_body"] = self.extra_body
        response = self._client.chat.completions.create(**params)
        choices = getattr(response, "choices", []) or []
        if not choices:
            return "", {
                "request_id": getattr(response, "id", None),
                "usage": self._serializable(getattr(response, "usage", None)),
            }
        choice = choices[0]
        message = getattr(choice, "message", None)
        content = getattr(message, "content", "") or ""
        if isinstance(content, list):
            content = "".join(
                str(getattr(part, "text", "") or (part.get("text", "") if isinstance(part, dict) else ""))
                for part in content
            )
        metadata = {
            "request_id": getattr(response, "id", None),
            "finish_reason": getattr(choice, "finish_reason", None),
            "usage": self._serializable(getattr(response, "usage", None)),
        }
        reasoning_content = getattr(message, "reasoning_content", None)
        metadata["reasoning_content_present"] = bool(reasoning_content)
        metadata["reasoning_content_chars"] = len(str(reasoning_content or ""))
        return str(content), metadata

    @staticmethod
    def _error_reason(error: Exception) -> str:
        name = type(error).__name__.lower()
        if "authentication" in name or "permission" in name:
            return "closed_llm_auth_error"
        if "ratelimit" in name or "rate_limit" in name:
            return "closed_llm_rate_limit"
        if "timeout" in name:
            return "closed_llm_timeout"
        if (
            "api" in name
            or "connection" in name
            or "badrequest" in name
            or "notfound" in name
            or "conflict" in name
            or "unprocessable" in name
            or "internalserver" in name
        ):
            return "closed_llm_api_error"
        return "closed_llm_invalid_response"

    def decompile(self, request: DecompileRequest, artifact_dir: Path) -> DecompileResult:
        started = time.perf_counter()
        prompt = self._build_prompt(request)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "model_prompt.txt").write_text(prompt, encoding="utf-8")
        metadata: dict[str, Any] = {
            "provider": self.provider,
            "model": self.model,
            "api_mode": self.api_mode,
            "thinking_mode": self.thinking_mode,
            "thinking_protocol": self.thinking_protocol,
            "sdk_max_retries": self.max_retries,
            "empty_output_retries": self.empty_output_retries,
            "attempts": [],
        }
        try:
            raw_output = ""
            code = ""
            extraction = "empty"
            total_attempts = self.empty_output_retries + 1
            for attempt in range(1, total_attempts + 1):
                raw_output, response_metadata = self._infer(prompt)
                code, extraction = extract_candidate_code(raw_output)
                attempt_record = {
                    "attempt": attempt,
                    "outcome": "success" if code else "empty_output",
                    "extraction": extraction,
                    **response_metadata,
                }
                metadata["attempts"].append(attempt_record)
                metadata.update(response_metadata)
                metadata["extraction"] = extraction
                metadata["attempt_count"] = attempt
                if code:
                    break
                if attempt < total_attempts:
                    delay = min(
                        self.empty_output_backoff_seconds * (2 ** (attempt - 1)),
                        self.empty_output_backoff_max_seconds,
                    )
                    attempt_record["retry_delay_seconds"] = delay
                    if delay:
                        time.sleep(delay)
            (artifact_dir / "response_metadata.json").write_text(
                json.dumps(metadata, ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
            if not code:
                return DecompileResult(
                    success=False,
                    raw_output=raw_output,
                    reason="closed_llm_empty_output",
                    log=f"Empty model output after {metadata['attempt_count']} attempts",
                    elapsed_seconds=time.perf_counter() - started,
                    backend_version=self.version,
                )
            return DecompileResult(
                success=True,
                raw_output=raw_output,
                code=code,
                reason=None,
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )
        except Exception as error:
            metadata["error_type"] = type(error).__name__
            (artifact_dir / "response_metadata.json").write_text(
                json.dumps(metadata, ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
            return DecompileResult(
                success=False,
                reason=self._error_reason(error),
                log=f"{type(error).__name__}: {error}",
                elapsed_seconds=time.perf_counter() - started,
                backend_version=self.version,
            )

    def decompile_many(
        self, requests: list[DecompileRequest], artifact_dirs: list[Path]
    ) -> list[DecompileResult]:
        if self.max_concurrency == 1 or len(requests) <= 1:
            return super().decompile_many(requests, artifact_dirs)
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as pool:
            return list(pool.map(lambda item: self.decompile(*item), zip(requests, artifact_dirs)))

    def close(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if close:
                close()
            self._client = None
