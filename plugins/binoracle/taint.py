from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ir import Instruction, MemoryOperand, Operand


SUPPORTED_ARGUMENT_REGISTERS = ("RDI", "RSI", "RDX", "RCX", "R8", "R9")
TRACKED_ARGUMENT_REGISTERS = ("RDI", "RSI", "RDX", "RCX", "R8", "R9")
CALLER_SAVED = ("RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11")


def _width(mnemonic: str) -> int:
    base = mnemonic.split(".", 1)[0]
    if base.endswith("b"):
        return 1
    if base.endswith("w"):
        return 2
    if base.endswith("l"):
        return 4
    return 8


def _is_move(mnemonic: str) -> bool:
    return mnemonic.startswith(("mov", "lea"))


def _is_compare(mnemonic: str) -> bool:
    return mnemonic.startswith(("cmp", "test"))


def _is_call(mnemonic: str) -> bool:
    return mnemonic.startswith("call")


def _is_return(mnemonic: str) -> bool:
    return mnemonic.startswith("ret")


def _is_unconditional_write(mnemonic: str) -> bool:
    return mnemonic.startswith(("mov", "lea", "pop"))


@dataclass(frozen=True)
class MemoryAccessEvidence:
    instruction_id: str
    argument_register: str
    via_register: str
    displacement: int | None
    width: int
    direction: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_id": self.instruction_id,
            "argument_register": self.argument_register,
            "via_register": self.via_register,
            "displacement": self.displacement,
            "width": self.width,
            "direction": self.direction,
        }


@dataclass(frozen=True)
class TaintAnalysis:
    argument_evidence: dict[str, tuple[str, ...]]
    pointer_evidence: dict[str, tuple[MemoryAccessEvidence, ...]]
    return_evidence: tuple[str, ...]
    return_taint: tuple[str, ...]
    trace: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "binoracle.taint.v1",
            "argument_evidence": {
                key: list(value) for key, value in sorted(self.argument_evidence.items())
            },
            "pointer_evidence": {
                key: [item.to_dict() for item in value]
                for key, value in sorted(self.pointer_evidence.items())
            },
            "return_evidence": list(self.return_evidence),
            "return_taint": list(self.return_taint),
            "trace": list(self.trace),
        }


class TaintAnalyzer:
    def __init__(self) -> None:
        self.registers: dict[str, frozenset[str]] = {
            register: frozenset({f"arg:{register}"})
            for register in TRACKED_ARGUMENT_REGISTERS
        }
        self.stack: dict[tuple[str, int], frozenset[str]] = {}
        self.argument_evidence: dict[str, list[str]] = {
            register: [] for register in TRACKED_ARGUMENT_REGISTERS
        }
        self.pointer_evidence: dict[str, list[MemoryAccessEvidence]] = {
            register: [] for register in TRACKED_ARGUMENT_REGISTERS
        }
        self.trace: list[dict[str, Any]] = []
        self.rax_defined = False
        self.return_evidence: list[str] = []
        self.return_taint: set[str] = set()
        self.defined_registers: set[str] = set()

    def _register_taint(self, register: str | None) -> frozenset[str]:
        return self.registers.get(register or "", frozenset())

    def _address_taint(self, memory: MemoryOperand) -> frozenset[str]:
        return self._register_taint(memory.base) | self._register_taint(memory.index)

    def _stack_key(self, memory: MemoryOperand) -> tuple[str, int] | None:
        if memory.base in {"RBP", "RSP"} and memory.index is None:
            return memory.base, int(memory.displacement or 0)
        return None

    def _value_taint(self, operand: Operand) -> frozenset[str]:
        if operand.kind == "register":
            return self._register_taint(operand.register)
        if operand.kind == "memory" and operand.memory is not None:
            key = self._stack_key(operand.memory)
            if key is not None:
                return self.stack.get(key, frozenset())
        return frozenset()

    def _record_argument_use(self, taint: frozenset[str], instruction_id: str) -> None:
        for origin in sorted(taint):
            if not origin.startswith("arg:"):
                continue
            register = origin.split(":", 1)[1]
            evidence = self.argument_evidence.get(register)
            if evidence is not None and instruction_id not in evidence:
                evidence.append(instruction_id)

    def _memory_direction(self, instruction: Instruction, index: int) -> str:
        last = len(instruction.operands) - 1
        if _is_compare(instruction.mnemonic):
            return "read"
        if _is_unconditional_write(instruction.mnemonic) and index == last:
            return "write"
        if index == last:
            return "read_write"
        return "read"

    def _record_memory(
        self, instruction: Instruction, operand: Operand, index: int
    ) -> None:
        assert operand.memory is not None
        memory = operand.memory
        address_taint = self._address_taint(memory)
        self._record_argument_use(address_taint, instruction.instruction_id)
        direction = self._memory_direction(instruction, index)
        for origin in sorted(address_taint):
            if not origin.startswith("arg:"):
                continue
            register = origin.split(":", 1)[1]
            if register not in self.pointer_evidence:
                continue
            self.pointer_evidence[register].append(
                MemoryAccessEvidence(
                    instruction_id=instruction.instruction_id,
                    argument_register=register,
                    via_register=memory.base or memory.index or "UNKNOWN",
                    displacement=memory.displacement,
                    width=_width(instruction.mnemonic),
                    direction=direction,
                )
            )

    def _write_destination(
        self, instruction: Instruction, destination: Operand, source_taint: frozenset[str]
    ) -> None:
        if destination.kind == "register" and destination.register is not None:
            previous = self._register_taint(destination.register)
            if instruction.mnemonic.startswith(("xor", "sub")) and len(instruction.operands) >= 2:
                left, right = instruction.operands[-2:]
                if (
                    left.kind == right.kind == "register"
                    and left.register == right.register == destination.register
                ):
                    source_taint = frozenset()
            elif not _is_unconditional_write(instruction.mnemonic):
                source_taint = source_taint | previous
            self.registers[destination.register] = source_taint
            self.defined_registers.add(destination.register)
            if destination.register == "RAX":
                self.rax_defined = True
        elif destination.kind == "memory" and destination.memory is not None:
            key = self._stack_key(destination.memory)
            if key is not None:
                self.stack[key] = source_taint

    def analyze(self, instructions: tuple[Instruction, ...]) -> TaintAnalysis:
        for instruction in instructions:
            before = {
                key: sorted(value) for key, value in self.registers.items() if value
            }
            operands = instruction.operands
            destination = operands[-1] if operands and not _is_compare(instruction.mnemonic) else None
            source_operands = operands[:-1] if destination is not None else operands

            for index, operand in enumerate(operands):
                if (
                    operand.kind == "memory"
                    and not instruction.mnemonic.startswith(("lea", "nop"))
                ):
                    self._record_memory(instruction, operand, index)

            source_taint = frozenset()
            for operand in source_operands:
                value_taint = self._value_taint(operand)
                source_taint |= value_taint
                self._record_argument_use(value_taint, instruction.instruction_id)
            if instruction.mnemonic.startswith("lea") and source_operands:
                memory = source_operands[0].memory
                if memory is not None:
                    source_taint |= self._address_taint(memory)
                    if memory.symbol:
                        source_taint |= frozenset({f"symbol:{memory.symbol}"})
                    self._record_argument_use(
                        self._address_taint(memory), instruction.instruction_id
                    )

            if destination is not None:
                if not _is_unconditional_write(instruction.mnemonic):
                    destination_taint = self._value_taint(destination)
                    source_taint |= destination_taint
                    self._record_argument_use(
                        destination_taint, instruction.instruction_id
                    )
                self._write_destination(instruction, destination, source_taint)

            if _is_call(instruction.mnemonic):
                # Untouched SysV call registers contain unspecified entry values. Counting
                # all of them as call-site evidence creates false RDX/RCX/R8/R9 parameters
                # around calls such as printf. Keep values prepared by this function or
                # arguments already observed by another instruction.
                call_taint = frozenset().union(
                    *(
                        self._register_taint(register)
                        for register in TRACKED_ARGUMENT_REGISTERS
                        if register in self.defined_registers
                        or self.argument_evidence[register]
                    )
                )
                self._record_argument_use(call_taint, instruction.instruction_id)
                for register in CALLER_SAVED:
                    self.registers[register] = frozenset()
                self.rax_defined = True
            if _is_return(instruction.mnemonic):
                self.return_taint.update(self._register_taint("RAX"))
                if self.rax_defined:
                    self.return_evidence.append(
                        f"{instruction.instruction_id}:rax_defined_before_return"
                    )
                else:
                    self.return_evidence.append(
                        f"{instruction.instruction_id}:rax_not_defined_before_return"
                    )

            after = {
                key: sorted(value) for key, value in self.registers.items() if value
            }
            self.trace.append(
                {
                    "instruction_id": instruction.instruction_id,
                    "mnemonic": instruction.mnemonic,
                    "register_taint_before": before,
                    "register_taint_after": after,
                }
            )

        return TaintAnalysis(
            argument_evidence={
                key: tuple(value)
                for key, value in self.argument_evidence.items()
                if value
            },
            pointer_evidence={
                key: tuple(value)
                for key, value in self.pointer_evidence.items()
                if value
            },
            return_evidence=tuple(self.return_evidence),
            return_taint=tuple(sorted(self.return_taint)),
            trace=tuple(self.trace),
        )


def analyze_taint(instructions: tuple[Instruction, ...]) -> TaintAnalysis:
    return TaintAnalyzer().analyze(instructions)
