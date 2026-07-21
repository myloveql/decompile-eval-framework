from __future__ import annotations

import hashlib
from pathlib import Path

from .dependencies import classify_dependencies
from .elf_parser import ELFParseError, parse_elf_file
from .relocations import relocations_for_symbol
from .schemas import BinaryFacts
from .symbol_table import SymbolTableError, collect_global_objects, select_target_symbol


_ELF_TYPES = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN"}
_MACHINES = {3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64"}


class BinaryFactError(ValueError):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def extract_binary_facts(
    path: Path,
    *,
    target_function: str,
    require_relocatable: bool,
) -> BinaryFacts:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise BinaryFactError("binary_missing", f"binary does not exist: {resolved}")
    data = resolved.read_bytes()
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise BinaryFactError("unsupported_binary_format", "BinOracle requires an ELF binary")

    elf_class = {1: 32, 2: 64}.get(data[4])
    if elf_class is None:
        raise BinaryFactError("unsupported_elf_class", f"unsupported ELF class byte: {data[4]}")
    byteorder = {1: "little", 2: "big"}.get(data[5])
    if byteorder is None:
        raise BinaryFactError(
            "unsupported_elf_endianness", f"unsupported ELF endianness byte: {data[5]}"
        )
    elf_type_value = int.from_bytes(data[16:18], byteorder=byteorder)
    machine_value = int.from_bytes(data[18:20], byteorder=byteorder)
    elf_type = _ELF_TYPES.get(elf_type_value, f"UNKNOWN({elf_type_value})")
    machine = _MACHINES.get(machine_value, f"UNKNOWN({machine_value})")
    if require_relocatable and elf_type != "ET_REL":
        raise BinaryFactError(
            "unsupported_elf_type",
            f"strict BinOracle mode requires ET_REL input, got {elf_type}",
        )
    if machine != "x86_64":
        raise BinaryFactError(
            "unsupported_architecture", f"BinOracle V1 only supports x86_64, got {machine}"
        )

    try:
        parsed = parse_elf_file(resolved)
    except (ELFParseError, SymbolTableError) as error:
        raise BinaryFactError("elf_parse_error", str(error)) from error
    try:
        target = select_target_symbol(parsed.symbols, target_function)
    except SymbolTableError as error:
        raise BinaryFactError("target_symbol_missing", str(error)) from error
    undefined = sorted({
        item["name"] for item in parsed.symbols
        if item["undefined"] and item["name"] and item["type"] in {"FUNC", "NOTYPE"}
    })
    target_relocations = relocations_for_symbol(parsed.relocations, target)
    referenced_names = {
        str(item["symbol"]) for item in target_relocations if item.get("symbol")
    }
    globals_ = collect_global_objects(parsed.symbols, referenced_names=referenced_names)
    dependencies = classify_dependencies(undefined, target_relocations)

    return BinaryFacts(
        path=str(resolved),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        elf_class=elf_class,
        endianness=byteorder,
        elf_type=elf_type,
        machine=machine,
        target_function=target_function,
        target=target,
        sections=parsed.sections,
        symbols=parsed.symbols,
        relocations=target_relocations,
        undefined_symbols=tuple(undefined),
        global_objects=globals_,
        dependencies=dependencies,
    )
