from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_REGISTER_GROUPS = {
    "RAX": ("rax", "eax", "ax", "al", "ah"),
    "RBX": ("rbx", "ebx", "bx", "bl", "bh"),
    "RCX": ("rcx", "ecx", "cx", "cl", "ch"),
    "RDX": ("rdx", "edx", "dx", "dl", "dh"),
    "RSI": ("rsi", "esi", "si", "sil"),
    "RDI": ("rdi", "edi", "di", "dil"),
    "RBP": ("rbp", "ebp", "bp", "bpl"),
    "RSP": ("rsp", "esp", "sp", "spl"),
    **{
        f"R{index}": (f"r{index}", f"r{index}d", f"r{index}w", f"r{index}b")
        for index in range(8, 16)
    },
}
REGISTER_ALIASES = {
    alias: canonical
    for canonical, aliases in _REGISTER_GROUPS.items()
    for alias in aliases
}


def canonical_register(value: str | None) -> str | None:
    if value is None:
        return None
    return REGISTER_ALIASES.get(value.lower().lstrip("%"))


def _split_operands(value: str) -> tuple[str, ...]:
    result: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(value):
        if character in "([":
            depth += 1
        elif character in ")]":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        result.append(tail)
    return tuple(result)


def _integer(value: str) -> int | None:
    cleaned = value.strip().lower()
    if not cleaned:
        return 0
    try:
        return int(cleaned, 0)
    except ValueError:
        return None


@dataclass(frozen=True)
class MemoryOperand:
    base: str | None
    index: str | None
    scale: int
    displacement: int | None
    symbol: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": self.base,
            "index": self.index,
            "scale": self.scale,
            "displacement": self.displacement,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class Operand:
    text: str
    kind: str
    register: str | None = None
    immediate: int | None = None
    memory: MemoryOperand | None = None

    def to_dict(self) -> dict[str, Any]:
        value = {
            "text": self.text,
            "kind": self.kind,
            "register": self.register,
            "immediate": self.immediate,
        }
        if self.memory is not None:
            value["memory"] = self.memory.to_dict()
        return value


@dataclass(frozen=True)
class Instruction:
    instruction_id: str
    line_number: int
    mnemonic: str
    operands: tuple[Operand, ...]
    syntax: str
    source_text: str
    address: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_id": self.instruction_id,
            "line_number": self.line_number,
            "address": self.address,
            "mnemonic": self.mnemonic,
            "operands": [item.to_dict() for item in self.operands],
            "syntax": self.syntax,
            "source_text": self.source_text,
        }


def _parse_att_memory(text: str) -> MemoryOperand | None:
    match = re.fullmatch(
        r"(?P<prefix>[^()]*)\((?P<body>[^()]*)\)", text.strip()
    )
    if not match:
        return None
    prefix = match.group("prefix").strip()
    body = [item.strip() for item in match.group("body").split(",")]
    base = canonical_register(body[0]) if body and body[0] else None
    index = canonical_register(body[1]) if len(body) > 1 and body[1] else None
    scale = _integer(body[2]) if len(body) > 2 and body[2] else 1
    displacement = _integer(prefix)
    symbol = None if displacement is not None else prefix or None
    return MemoryOperand(base, index, int(scale or 1), displacement, symbol)


def _parse_intel_memory(text: str) -> MemoryOperand | None:
    match = re.search(r"\[([^]]+)\]", text)
    if not match:
        return None
    expression = match.group(1).replace("-", "+-")
    base = None
    index = None
    scale = 1
    displacement = 0
    symbol_parts: list[str] = []
    for raw in expression.split("+"):
        part = raw.strip()
        if not part:
            continue
        if "*" in part:
            name, raw_scale = (item.strip() for item in part.split("*", 1))
            register = canonical_register(name)
            if register is not None:
                index = register
                scale = _integer(raw_scale) or 1
                continue
        register = canonical_register(part)
        if register is not None:
            if base is None:
                base = register
            elif index is None:
                index = register
            continue
        number = _integer(part)
        if number is not None:
            displacement += number
        else:
            symbol_parts.append(part)
    return MemoryOperand(
        base=base,
        index=index,
        scale=scale,
        displacement=displacement,
        symbol="+".join(symbol_parts) or None,
    )


def _parse_operand(text: str, *, syntax: str) -> Operand:
    cleaned = text.strip()
    memory = (
        _parse_att_memory(cleaned)
        if syntax == "att"
        else _parse_intel_memory(cleaned)
    )
    if memory is not None:
        return Operand(cleaned, "memory", memory=memory)
    register = canonical_register(cleaned)
    if register is not None:
        return Operand(cleaned, "register", register=register)
    immediate_text = cleaned.lstrip("$")
    immediate = _integer(immediate_text)
    if immediate is not None:
        return Operand(cleaned, "immediate", immediate=immediate)
    return Operand(cleaned, "symbol")


def _syntax_for_line(line: str, requested: str) -> str:
    lowered = requested.lower()
    if "att" in lowered or "at&t" in lowered:
        return "att"
    if "intel" in lowered:
        return "intel"
    return "att" if "%" in line or re.search(r"\([^)]*%", line) else "intel"


def parse_assembly(assembly: str, *, syntax: str = "auto") -> tuple[Instruction, ...]:
    instructions: list[Instruction] = []
    for line_number, raw in enumerate(assembly.splitlines(), 1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.endswith(":"):
            continue
        address = None
        address_match = re.match(r"^(?P<address>[0-9a-fA-F]+):\s*(?P<body>.*)$", line)
        if address_match:
            address = int(address_match.group("address"), 16)
            line = address_match.group("body").strip()
        match = re.match(r"^(?P<mnemonic>[A-Za-z][A-Za-z0-9_.]*)\s*(?P<ops>.*)$", line)
        if not match:
            continue
        line_syntax = _syntax_for_line(line, syntax)
        raw_operands = _split_operands(match.group("ops"))
        if line_syntax == "intel" and len(raw_operands) > 1:
            raw_operands = tuple(reversed(raw_operands))
        operands = tuple(
            _parse_operand(item, syntax=line_syntax) for item in raw_operands
        )
        index = len(instructions)
        instructions.append(
            Instruction(
                instruction_id=f"insn:{index}",
                line_number=line_number,
                mnemonic=match.group("mnemonic").lower(),
                operands=operands,
                syntax=line_syntax,
                source_text=raw.strip(),
                address=address,
            )
        )
    return tuple(instructions)
