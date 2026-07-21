from __future__ import annotations

import re

from .schemas import ArgumentSpec, ContractGraph, ObjectSpec, ReturnSpec


_SLOTS = ("RDI", "RSI", "RDX", "RCX", "R8", "R9")
_REG_ALIASES = {
    "RDI": ("rdi", "edi", "di", "dil"),
    "RSI": ("rsi", "esi", "si", "sil"),
    "RDX": ("rdx", "edx", "dx", "dl"),
    "RCX": ("rcx", "ecx", "cx", "cl"),
    "R8": ("r8", "r8d", "r8w", "r8b"),
    "R9": ("r9", "r9d", "r9w", "r9b"),
}


def _mentions(text: str, aliases: tuple[str, ...]) -> bool:
    return any(re.search(rf"(?<![a-z0-9_])%?{name}(?![a-z0-9_])", text) for name in aliases)


def _memory_base(text: str, aliases: tuple[str, ...]) -> bool:
    for name in aliases:
        if re.search(rf"\([^)]*%{name}(?:[,)]|$)", text):
            return True
        if re.search(rf"\[[^]]*(?<![a-z0-9_]){name}(?![a-z0-9_])[^]]*\]", text):
            return True
    return False


def _read_before_def_slots(assembly: str) -> set[str]:
    """Conservatively identify SysV argument registers read before overwrite.

    This is intentionally small and auditable. It handles the common AT&T/Intel
    move/lea destination forms and self-xor zeroing; ambiguous read-modify-write
    instructions count as reads. Full SSA/alias propagation belongs to the P-code
    implementation planned after the backend MVP.
    """

    states = {slot: "unseen" for slot in _SLOTS}
    for raw_line in assembly.splitlines():
        line = raw_line.split("#", 1)[0].strip().lower()
        if not line or line.endswith(":"):
            continue
        match = re.search(r"\b([a-z][a-z0-9.]*)\s+(.+)$", line)
        if not match:
            continue
        mnemonic, operand_text = match.groups()
        operands = [item.strip() for item in operand_text.split(",")]
        for slot in _SLOTS:
            if states[slot] != "unseen":
                continue
            aliases = _REG_ALIASES[slot]
            if not _mentions(operand_text, aliases):
                continue
            self_xor = mnemonic.startswith(("xor", "sub")) and len(operands) >= 2
            if self_xor and all(_mentions(item, aliases) for item in operands[-2:]):
                states[slot] = "defined"
                continue
            write_only = mnemonic.startswith(("mov", "lea", "pop"))
            if write_only and operands:
                destination = operands[-1]
                sources = operands[:-1]
                destination_is_register = _mentions(destination, aliases) and not any(
                    marker in destination for marker in ("(", ")", "[", "]")
                )
                source_mentions = any(_mentions(item, aliases) for item in sources)
                if destination_is_register and not source_mentions:
                    states[slot] = "defined"
                    continue
            states[slot] = "read"
    return {slot for slot, state in states.items() if state == "read"}


def _access_width(line: str) -> int:
    mnemonic = line.strip().split(maxsplit=1)[0].lower() if line.strip() else ""
    if mnemonic.endswith("b"):
        return 1
    if mnemonic.endswith("w"):
        return 2
    if mnemonic.endswith("l"):
        return 4
    return 8


def _max_direct_offset(assembly: str, aliases: tuple[str, ...]) -> tuple[int, list[tuple[int, int]]]:
    accesses: list[tuple[int, int]] = []
    names = "|".join(re.escape(name) for name in aliases)
    att = re.compile(rf"(?P<off>-?(?:0x[0-9a-f]+|\d+))?\(%?(?:{names})(?:[,)]|$)", re.I)
    intel = re.compile(
        rf"\[[^]]*\b(?:{names})\b\s*(?:\+\s*(?P<off>0x[0-9a-f]+|\d+))?[^]]*\]",
        re.I,
    )
    for line in assembly.splitlines():
        match = att.search(line) or intel.search(line)
        if not match:
            continue
        raw = match.groupdict().get("off")
        offset = int(raw, 0) if raw else 0
        if offset < 0:
            continue
        accesses.append((offset, _access_width(line)))
    return max((offset + width for offset, width in accesses), default=0), accesses


def infer_contract(assembly: str, *, abi: str = "sysv-x86_64") -> ContractGraph:
    lowered = assembly.lower()
    arguments: list[ArgumentSpec] = []
    objects: list[ObjectSpec] = []
    input_slots = _read_before_def_slots(lowered)
    for slot in _SLOTS:
        aliases = _REG_ALIASES[slot]
        if slot not in input_slots:
            continue
        is_pointer = _memory_base(lowered, aliases)
        object_ref = f"obj{len(objects)}" if is_pointer else None
        evidence = [f"assembly_mentions:{slot}"]
        candidates = ("pointer", "integer") if is_pointer else ("integer", "pointer")
        confidence = 0.82 if is_pointer else 0.58
        if is_pointer:
            minimum, accesses = _max_direct_offset(lowered, aliases)
            objects.append(
                ObjectSpec(
                    object_id=object_ref or "",
                    argument_slot=slot,
                    min_size=max(1, minimum),
                    alignment=8,
                    reads=tuple(accesses),
                )
            )
            evidence.append("memory_base_use")
        arguments.append(
            ArgumentSpec(
                slot=slot,
                kind_candidates=candidates,
                confidence=confidence,
                evidence=tuple(evidence),
                object_ref=object_ref,
            )
        )

    writes_return = bool(
        re.search(r"\b(?:mov|lea|xor|add|sub|and|or)[a-z]*\b[^\n]*(?:%e?ax\b|\be?ax\b)", lowered)
    )
    return_spec = ReturnSpec(
        kind="integer_or_void" if writes_return else "void_or_unknown",
        confidence=0.4 if writes_return else 0.35,
        # A standalone callee writing RAX does not prove a source-level return value:
        # void functions routinely leave temporary values in RAX. Stay conservative.
        observable=False,
        evidence=("rax_defined_but_source_return_unknown",)
        if writes_return
        else ("no_stable_rax_definition",),
    )
    confidences = [item.confidence for item in arguments] + [return_spec.confidence]
    return ContractGraph(
        contract_id="K_static_0",
        abi=abi,
        arguments=tuple(arguments),
        return_spec=return_spec,
        objects=tuple(objects),
        confidence=sum(confidences) / len(confidences) if confidences else return_spec.confidence,
        limitations=(
            "heuristic_static_contract",
            "no_dynamic_probe_in_backend_mvp",
            "read_write_direction_not_yet_disambiguated",
        ),
    )
