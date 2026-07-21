from __future__ import annotations

import json
import hashlib
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .privacy import find_private_metadata_paths


class RepairProtocolError(ValueError):
    pass


class RepairState(str, Enum):
    INITIAL = "initial"
    COMPILE = "compile"
    LINK = "link"
    DIFFERENTIAL = "differential"
    MINIMIZE = "minimize"
    REPAIR = "repair"
    FULL_REGRESSION = "full_regression"
    ACCEPTED = "accepted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


_TRANSITIONS = {
    RepairState.INITIAL: {RepairState.COMPILE, RepairState.UNSUPPORTED},
    RepairState.COMPILE: {RepairState.LINK, RepairState.REPAIR, RepairState.FAILED},
    RepairState.LINK: {RepairState.DIFFERENTIAL, RepairState.REPAIR, RepairState.FAILED},
    RepairState.DIFFERENTIAL: {
        RepairState.MINIMIZE,
        RepairState.FULL_REGRESSION,
        RepairState.REPAIR,
        RepairState.FAILED,
    },
    RepairState.MINIMIZE: {RepairState.REPAIR, RepairState.FAILED},
    RepairState.REPAIR: {
        RepairState.COMPILE,
        RepairState.BUDGET_EXHAUSTED,
        RepairState.FAILED,
    },
    RepairState.FULL_REGRESSION: {RepairState.ACCEPTED, RepairState.REPAIR, RepairState.FAILED},
}


def validate_transition(current: RepairState, target: RepairState) -> None:
    if target not in _TRANSITIONS.get(current, set()):
        raise RepairProtocolError(f"illegal repair state transition: {current.value} -> {target.value}")


@dataclass(frozen=True)
class RepairBudget:
    iterations_remaining: int
    executions_remaining: int
    model_calls_remaining: int = 0
    tokens_remaining: int = 0

    def __post_init__(self) -> None:
        if min(
            self.iterations_remaining,
            self.executions_remaining,
            self.model_calls_remaining,
            self.tokens_remaining,
        ) < 0:
            raise RepairProtocolError("repair budget values must be non-negative")

    def to_dict(self) -> dict[str, int]:
        return {
            "iterations_remaining": self.iterations_remaining,
            "executions_remaining": self.executions_remaining,
            "model_calls_remaining": self.model_calls_remaining,
            "tokens_remaining": self.tokens_remaining,
        }


@dataclass(frozen=True)
class RepairRequest:
    sample_id: str
    candidate_source: str
    compile_diagnostics: str
    frozen_harness_hash: str
    evidence_packages: tuple[dict[str, Any], ...]
    allowed_edit_scope: tuple[str, ...]
    iteration: int
    remaining_budget: RepairBudget

    def __post_init__(self) -> None:
        if not self.sample_id or not self.candidate_source.strip():
            raise RepairProtocolError("repair request requires sample_id and candidate_source")
        if not re.fullmatch(r"[0-9a-f]{64}", self.frozen_harness_hash):
            raise RepairProtocolError("frozen_harness_hash must be a SHA-256 digest")
        if self.iteration < 0:
            raise RepairProtocolError("repair iteration must be non-negative")
        if not self.allowed_edit_scope:
            raise RepairProtocolError("allowed_edit_scope must not be empty")
        leaked = find_private_metadata_paths(
            {"evidence_packages": self.evidence_packages}, prefix="repair_request"
        )
        if leaked:
            raise RepairProtocolError(
                "repair request contains private fields: " + ", ".join(leaked)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.repair-request.v1",
            "sample_id": self.sample_id,
            "candidate_source": self.candidate_source,
            "compile_diagnostics": self.compile_diagnostics,
            "frozen_harness_hash": self.frozen_harness_hash,
            "evidence_packages": list(self.evidence_packages),
            "allowed_edit_scope": list(self.allowed_edit_scope),
            "iteration": self.iteration,
            "remaining_budget": self.remaining_budget.to_dict(),
        }


@dataclass(frozen=True)
class RepairResponse:
    revised_source: str
    rationale_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    changed_regions: tuple[str, ...]
    abstain: bool

    def __post_init__(self) -> None:
        if self.abstain:
            if self.revised_source or self.changed_regions:
                raise RepairProtocolError("abstaining response must not contain edits")
            return
        if not self.revised_source.strip():
            raise RepairProtocolError("non-abstaining response requires revised_source")
        if not self.rationale_codes or not self.evidence_ids or not self.changed_regions:
            raise RepairProtocolError(
                "non-abstaining response requires rationale, evidence, and changed regions"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.repair-response.v1",
            "revised_source": self.revised_source,
            "rationale_codes": list(self.rationale_codes),
            "evidence_ids": list(self.evidence_ids),
            "changed_regions": list(self.changed_regions),
            "abstain": self.abstain,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RepairResponse":
        expected = {
            "revised_source",
            "rationale_codes",
            "evidence_ids",
            "changed_regions",
            "abstain",
        }
        unknown = set(value) - expected
        missing = expected - set(value)
        if unknown or missing:
            raise RepairProtocolError(
                f"invalid repair response fields; missing={sorted(missing)}, "
                f"unknown={sorted(unknown)}"
            )
        if not isinstance(value["abstain"], bool):
            raise RepairProtocolError("repair response abstain must be boolean")
        for name in ("rationale_codes", "evidence_ids", "changed_regions"):
            if not isinstance(value[name], list) or not all(
                isinstance(item, str) for item in value[name]
            ):
                raise RepairProtocolError(f"repair response {name} must be a string array")
        if not isinstance(value["revised_source"], str):
            raise RepairProtocolError("repair response revised_source must be a string")
        return cls(
            revised_source=value["revised_source"],
            rationale_codes=tuple(value["rationale_codes"]),
            evidence_ids=tuple(value["evidence_ids"]),
            changed_regions=tuple(value["changed_regions"]),
            abstain=value["abstain"],
        )

    @classmethod
    def abstained(cls, reason: str) -> "RepairResponse":
        return cls("", (reason,), (), (), True)


_UNDECLARED_PATTERNS = (
    re.compile(r"[‘']([A-Za-z_$][A-Za-z0-9_$]*)[’'] undeclared"),
    re.compile(r"use of undeclared identifier [‘']([A-Za-z_$][A-Za-z0-9_$]*)[’']"),
)


def _declaration_for_global(value: dict[str, Any]) -> str | None:
    """Return only an independently supplied public source declaration.

    ELF object size establishes ABI storage width, not the original C type.  In
    particular it cannot distinguish size_t, pointers, and integer types on
    LP64.  Repair must therefore abstain unless a separately curated public
    declaration is attached to the fact by the caller.
    """
    declaration = value.get("public_c_declaration")
    if not isinstance(declaration, str):
        return None
    declaration = declaration.strip()
    name = str(value.get("name") or "")
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
        return None
    if not re.fullmatch(
        rf"extern\s+[^;{{}}]+\b{re.escape(name)}\s*;", declaration
    ):
        return None
    return declaration


class DeterministicRepairer:
    version = "binoracle-deterministic-repairer-v1"

    def repair(
        self, request: RepairRequest, *, binary_facts: dict[str, Any]
    ) -> RepairResponse:
        identifiers = {
            match.group(1)
            for pattern in _UNDECLARED_PATTERNS
            for match in pattern.finditer(request.compile_diagnostics)
        }
        globals_by_name = {
            str(value.get("name")): value
            for value in binary_facts.get("global_objects", [])
        }
        declarations = [
            declaration
            for name in sorted(identifiers)
            if name in globals_by_name
            if (declaration := _declaration_for_global(globals_by_name[name])) is not None
            if declaration not in request.candidate_source
        ]
        if not declarations:
            return RepairResponse.abstained("insufficient_public_evidence")
        revised = "\n".join(declarations) + "\n" + request.candidate_source.lstrip()
        evidence = tuple(f"compile:undefined_global:{line.split()[-1][:-1]}" for line in declarations)
        return RepairResponse(
            revised_source=revised,
            rationale_codes=("declare_binary_global_object",),
            evidence_ids=evidence,
            changed_regions=("public_declarations",),
            abstain=False,
        )

    def pop_audit_metadata(self) -> dict[str, Any] | None:
        return None


_REPAIR_RESPONSE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "revised_source",
        "rationale_codes",
        "evidence_ids",
        "changed_regions",
        "abstain",
    ],
    "properties": {
        "revised_source": {"type": "string"},
        "rationale_codes": {"type": "array", "items": {"type": "string"}},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "changed_regions": {"type": "array", "items": {"type": "string"}},
        "abstain": {"type": "boolean"},
    },
}


class OpenAIRepairer:
    """Evidence-bounded repair through the OpenAI Responses API."""

    prompt_version = "binoracle-openai-repair-prompt-v1"

    def __init__(
        self,
        *,
        model: str = "gpt-5.6-terra",
        max_output_tokens: int = 4096,
        reasoning_effort: str = "medium",
        client: Any | None = None,
    ) -> None:
        if max_output_tokens <= 0:
            raise ValueError("repair max_output_tokens must be positive")
        if reasoning_effort not in {"none", "minimal", "low", "medium", "high", "xhigh"}:
            raise ValueError("unsupported repair reasoning_effort")
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.reasoning_effort = reasoning_effort
        self._client = client
        self._last_audit: dict[str, Any] | None = None
        self.version = f"binoracle-openai-repairer-v1:{model}:{self.prompt_version}"

    @staticmethod
    def _serializable(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool, list, dict)):
            return value
        if hasattr(value, "model_dump"):
            return value.model_dump()
        return str(value)

    def _get_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI()
        return self._client

    def repair(
        self, request: RepairRequest, *, binary_facts: dict[str, Any]
    ) -> RepairResponse:
        del binary_facts  # The remote model receives only the public repair protocol.
        if request.remaining_budget.model_calls_remaining <= 0:
            return RepairResponse.abstained("model_call_budget_exhausted")
        if request.remaining_budget.tokens_remaining <= 0:
            return RepairResponse.abstained("model_token_budget_exhausted")
        allowed_evidence_ids = {
            str(item.get("evidence_id"))
            for item in request.evidence_packages
            if item.get("evidence_id")
        }
        if request.compile_diagnostics.strip():
            allowed_evidence_ids.add("compile:diagnostics")
        instructions = (
            "You are the bounded repair component of BinOracle. Use only the supplied "
            "public candidate, compiler diagnostics, frozen differential evidence, and "
            "edit scope. Never invent binary facts, hidden tests, symbols, or evidence. "
            "Preserve the target function ABI and do not add includes, file/network/process "
            "access, inline assembly, pragmas, attributes, or unrelated functions. Return "
            "abstain=true with empty revised_source, evidence_ids, and changed_regions when "
            "the evidence is insufficient. For an edit, cite only supplied evidence IDs "
            "(or compile:diagnostics), and keep every changed region within allowed_edit_scope."
        )
        payload = request.to_dict()
        payload["allowed_evidence_ids"] = sorted(allowed_evidence_ids)
        started = time.perf_counter()
        try:
            response = self._get_client().responses.create(
                model=self.model,
                instructions=instructions,
                input=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                max_output_tokens=min(
                    self.max_output_tokens,
                    request.remaining_budget.tokens_remaining,
                ),
                reasoning={"effort": self.reasoning_effort},
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "binoracle_repair_response",
                        "strict": True,
                        "schema": _REPAIR_RESPONSE_JSON_SCHEMA,
                    },
                    "verbosity": "low",
                },
                store=False,
                safety_identifier=(
                    "binoracle-"
                    + hashlib.sha256(request.sample_id.encode("utf-8")).hexdigest()[:32]
                ),
            )
            parsed = RepairResponse.from_dict(json.loads(str(response.output_text)))
            if not parsed.abstain:
                if not set(parsed.evidence_ids).issubset(allowed_evidence_ids):
                    raise RepairProtocolError("model cited evidence outside the repair request")
                if not set(parsed.changed_regions).issubset(request.allowed_edit_scope):
                    raise RepairProtocolError("model edited a region outside allowed_edit_scope")
            self._last_audit = {
                "schema_version": "binoracle.repair-model-call.v1",
                "provider": "openai",
                "model": self.model,
                "prompt_version": self.prompt_version,
                "request_id": getattr(response, "id", None),
                "status": getattr(response, "status", None),
                "usage": self._serializable(getattr(response, "usage", None)),
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "store": False,
                "outcome": "abstained" if parsed.abstain else "proposed_edit",
            }
            return parsed
        except Exception as error:
            self._last_audit = {
                "schema_version": "binoracle.repair-model-call.v1",
                "provider": "openai",
                "model": self.model,
                "prompt_version": self.prompt_version,
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "store": False,
                "outcome": "error",
                "error_type": type(error).__name__,
            }
            return RepairResponse.abstained(f"model_error:{type(error).__name__}")

    def pop_audit_metadata(self) -> dict[str, Any] | None:
        value = self._last_audit
        self._last_audit = None
        return value


class HybridRepairer:
    version: str

    def __init__(self, deterministic: DeterministicRepairer, model: OpenAIRepairer) -> None:
        self.deterministic = deterministic
        self.model = model
        self.version = f"binoracle-hybrid-repairer-v1:{model.model}:{model.prompt_version}"

    def repair(
        self, request: RepairRequest, *, binary_facts: dict[str, Any]
    ) -> RepairResponse:
        deterministic = self.deterministic.repair(request, binary_facts=binary_facts)
        if not deterministic.abstain:
            return deterministic
        return self.model.repair(request, binary_facts=binary_facts)

    def pop_audit_metadata(self) -> dict[str, Any] | None:
        return self.model.pop_audit_metadata()


__all__ = [
    "DeterministicRepairer",
    "HybridRepairer",
    "OpenAIRepairer",
    "RepairBudget",
    "RepairProtocolError",
    "RepairRequest",
    "RepairResponse",
    "RepairState",
    "validate_transition",
]
