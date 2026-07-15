#!/usr/bin/env python3
"""Convert GNU objdump output to symbolic Intel or AT&T instruction-only views."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


FUNCTION_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
ADDRESS_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*$")
RELOCATION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(R_X86_64_[A-Z0-9_]+)\s*$"
)
TARGET_RE = re.compile(r"\b([0-9a-fA-F]+)\s+<([^>]+)>")
NEGATIVE_RELOCATION_ADDEND_RE = re.compile(r"-0x[0-9a-fA-F]+$")


@dataclass
class Instruction:
    address: int
    text: str
    relocations: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class CleanResult:
    text: str
    function_name: str
    instruction_count: int
    relocation_count: int
    internal_label_count: int


def _parse(raw: str) -> tuple[str, list[Instruction]]:
    function_name = ""
    instructions: list[Instruction] = []
    current: Instruction | None = None

    for line in raw.splitlines():
        function_match = FUNCTION_RE.match(line)
        if function_match:
            function_name = function_match.group(2)
            continue

        parts = line.split("\t")
        if len(parts) == 3:
            address_match = ADDRESS_RE.match(parts[0])
            raw_bytes = parts[1].strip()
            instruction_text = parts[2].strip()
            if (
                address_match
                and instruction_text
                and re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", raw_bytes)
            ):
                current = Instruction(
                    address=int(address_match.group(1), 16),
                    text=instruction_text,
                )
                instructions.append(current)
                continue

        # objdump --no-show-raw-insn emits "address:\tinstruction". Raw-byte
        # continuation lines from ordinary objdump have the same tab shape,
        # so explicitly reject values consisting only of hexadecimal bytes.
        if len(parts) == 2:
            address_match = ADDRESS_RE.match(parts[0])
            instruction_text = parts[1].strip()
            if (
                address_match
                and instruction_text
                and not re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", instruction_text)
            ):
                current = Instruction(
                    address=int(address_match.group(1), 16),
                    text=instruction_text,
                )
                instructions.append(current)
                continue

        if "R_X86_64_" in line:
            relocation_parts = line.split("\t")
            if len(relocation_parts) >= 5 and current is not None:
                relocation_match = RELOCATION_RE.match(relocation_parts[-2])
                if relocation_match:
                    current.relocations.append(
                        (relocation_match.group(2), relocation_parts[-1].strip())
                    )

    if not function_name:
        raise ValueError("objdump function header was not found")
    if not instructions:
        raise ValueError(f"no instructions found for {function_name}")
    return function_name, instructions


def _symbolic_relocation(expression: str) -> str:
    # Negative addends in these relocatable objects compensate for PC-relative
    # encoding position. Positive offsets (for example bbox+0xc) are semantic.
    return NEGATIVE_RELOCATION_ADDEND_RE.sub("", expression)


def _normalize_instruction(
    instruction: Instruction,
    labels: dict[int, str],
    syntax: str,
) -> str:
    # Drop objdump's explanatory address comment, never operands such as 0x10.
    text = instruction.text.split("#", 1)[0].strip()

    for relocation_type, expression in instruction.relocations:
        symbol = _symbolic_relocation(expression)
        if relocation_type == "R_X86_64_PC32":
            if syntax == "intel":
                updated, count = re.subn(
                    r"rip\s*\+\s*0x0", f"rip + {symbol}", text,
                    count=1, flags=re.IGNORECASE,
                )
            else:
                updated, count = re.subn(
                    r"0x0\(%rip\)", f"{symbol}(%rip)", text, count=1,
                )
            if count != 1:
                raise ValueError(
                    f"cannot merge {relocation_type} {expression!r} into {text!r}"
                )
            text = updated
        elif relocation_type == "R_X86_64_PLT32":
            updated, count = TARGET_RE.subn(symbol, text, count=1)
            if count != 1:
                raise ValueError(
                    f"cannot merge {relocation_type} {expression!r} into {text!r}"
                )
            text = updated
        else:
            raise ValueError(f"unsupported relocation type: {relocation_type}")

    def replace_target(match: re.Match[str]) -> str:
        address = int(match.group(1), 16)
        return labels.get(address, match.group(2))

    text = TARGET_RE.sub(replace_target, text)
    mnemonic, separator, operands = text.partition(" ")
    if not separator:
        return mnemonic
    operands = re.sub(r"\s+", " ", operands.strip())
    operands = re.sub(r"\s*,\s*", ", ", operands)
    return f"{mnemonic} {operands}"


def _clean_objdump(raw: str, syntax: str) -> CleanResult:
    function_name, instructions = _parse(raw)
    addresses = {instruction.address for instruction in instructions}
    targets: set[int] = set()
    for instruction in instructions:
        for match in TARGET_RE.finditer(instruction.text.split("#", 1)[0]):
            address = int(match.group(1), 16)
            if address in addresses and address != instructions[0].address:
                targets.add(address)

    labels = {address: f".L_{address:x}" for address in sorted(targets)}
    output = [f"{function_name}:"]
    for instruction in instructions:
        if instruction.address in labels:
            output.append(f"{labels[instruction.address]}:")
        output.append(f"    {_normalize_instruction(instruction, labels, syntax)}")

    relocation_count = sum(len(item.relocations) for item in instructions)
    return CleanResult(
        text="\n".join(output) + "\n",
        function_name=function_name,
        instruction_count=len(instructions),
        relocation_count=relocation_count,
        internal_label_count=len(labels),
    )


def clean_objdump_intel(raw: str) -> CleanResult:
    return _clean_objdump(raw, "intel")


def clean_objdump_att(raw: str) -> CleanResult:
    return _clean_objdump(raw, "att")
