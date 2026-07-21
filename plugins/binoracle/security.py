from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


_FORBIDDEN_DIRECTIVES = re.compile(
    r"(?m)^\s*#\s*(include|include_next|pragma|line|embed)\b"
)
_FORBIDDEN_CALLS = re.compile(
    r"\b(system|popen|fork|vfork|clone|exec[a-zA-Z0-9_]*|open|openat|creat|fopen|"
    r"freopen|socket|socketpair|connect|bind|listen|accept|send|sendto|recv|recvfrom|"
    r"dlopen|dlsym|ptrace|mount|umount|unshare|setns|chroot|pivot_root|kill|syscall)\s*\("
)
_FORBIDDEN_LANGUAGE = re.compile(
    r"\b(__asm__|__asm|asm|_Pragma)\b|__attribute__\s*\(\([^)]*"
    r"(constructor|destructor|section|alias)"
)
_PATH_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*(?:/|\.\.)(?:[^"\\]|\\.)*"')


@dataclass(frozen=True)
class CandidateSecurityDecision:
    allowed: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.candidate-security.v1",
            "allowed": self.allowed,
            "reasons": list(self.reasons),
        }


def inspect_candidate_source(code: str) -> CandidateSecurityDecision:
    reasons: list[str] = []
    if _FORBIDDEN_DIRECTIVES.search(code):
        reasons.append("forbidden_preprocessor_directive")
    if _FORBIDDEN_CALLS.search(code):
        reasons.append("forbidden_system_or_process_call")
    if _FORBIDDEN_LANGUAGE.search(code):
        reasons.append("forbidden_inline_assembly_or_attribute")
    if _PATH_LITERAL.search(code):
        reasons.append("forbidden_path_literal")
    return CandidateSecurityDecision(not reasons, tuple(sorted(set(reasons))))


def sanitized_subprocess_environment() -> dict[str, str]:
    allowed = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TMP",
        "TEMP",
        "TMPDIR",
    )
    result = {name: os.environ[name] for name in allowed if name in os.environ}
    result.update({"LC_ALL": "C", "LANG": "C"})
    return result


__all__ = [
    "CandidateSecurityDecision",
    "inspect_candidate_source",
    "sanitized_subprocess_environment",
]
