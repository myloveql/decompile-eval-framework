from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ELFParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedELF:
    sections: tuple[dict[str, Any], ...]
    symbols: tuple[dict[str, Any], ...]
    relocations: tuple[dict[str, Any], ...]


_SECTION_TYPES = {
    0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB",
    4: "SHT_RELA", 8: "SHT_NOBITS", 9: "SHT_REL", 11: "SHT_DYNSYM",
}
_SYMBOL_TYPES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
_SYMBOL_BINDINGS = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
_X86_64_RELOCATIONS = {
    1: "R_X86_64_64", 2: "R_X86_64_PC32", 4: "R_X86_64_PLT32",
    9: "R_X86_64_GOTPCREL", 10: "R_X86_64_32", 11: "R_X86_64_32S",
    24: "R_X86_64_PC64", 41: "R_X86_64_GOTPCRELX", 42: "R_X86_64_REX_GOTPCRELX",
}


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_elf64(data: bytes) -> ParsedELF:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        raise ELFParseError("ELF64 input required")
    endian = "<" if data[5] == 1 else ">" if data[5] == 2 else None
    if endian is None:
        raise ELFParseError("invalid ELF byte order")
    header = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
    shoff, shentsize, shnum, shstrndx = header[6], header[11], header[12], header[13]
    if shentsize < 64 or shoff + shentsize * shnum > len(data):
        raise ELFParseError("section header table is out of bounds")
    raw_sections = []
    for index in range(shnum):
        values = struct.unpack_from(endian + "IIQQQQIIQQ", data, shoff + index * shentsize)
        raw_sections.append(values)
    if shstrndx >= len(raw_sections):
        raise ELFParseError("invalid section-name string table index")
    shstr = raw_sections[shstrndx]
    shstr_data = data[shstr[4]:shstr[4] + shstr[5]]
    sections: list[dict[str, Any]] = []
    for index, values in enumerate(raw_sections):
        name, kind, flags, address, offset, size, link, info, alignment, entsize = values
        sections.append({
            "index": index, "name": _cstring(shstr_data, name),
            "type": _SECTION_TYPES.get(kind, f"SHT_{kind}"), "type_value": kind,
            "flags": flags, "address": address, "offset": offset, "size": size,
            "link": link, "info": info, "alignment": alignment, "entry_size": entsize,
        })

    symbols: list[dict[str, Any]] = []
    symbols_by_table: dict[int, list[dict[str, Any]]] = {}
    for section in sections:
        if section["type_value"] not in (2, 11):
            continue
        link = section["link"]
        if link >= len(sections):
            continue
        strings = sections[link]
        string_data = data[strings["offset"]:strings["offset"] + strings["size"]]
        entry_size = section["entry_size"] or 24
        table: list[dict[str, Any]] = []
        for number, offset in enumerate(range(section["offset"], section["offset"] + section["size"], entry_size)):
            if offset + 24 > len(data):
                break
            name, info, other, shndx, value, size = struct.unpack_from(endian + "IBBHQQ", data, offset)
            item = {
                "table_section": section["index"], "index": number,
                "name": _cstring(string_data, name),
                "binding": _SYMBOL_BINDINGS.get(info >> 4, f"BIND_{info >> 4}"),
                "type": _SYMBOL_TYPES.get(info & 0xF, f"TYPE_{info & 0xF}"),
                "visibility": other & 3, "section_index": shndx,
                "section": sections[shndx]["name"] if 0 < shndx < len(sections) else None,
                "value": value, "size": size, "undefined": shndx == 0,
            }
            table.append(item)
            symbols.append(item)
        symbols_by_table[section["index"]] = table

    relocations: list[dict[str, Any]] = []
    for section in sections:
        if section["type_value"] not in (4, 9):
            continue
        symbol_table = symbols_by_table.get(section["link"], [])
        entry_size = section["entry_size"] or (24 if section["type_value"] == 4 else 16)
        for offset in range(section["offset"], section["offset"] + section["size"], entry_size):
            if section["type_value"] == 4:
                if offset + 24 > len(data):
                    break
                r_offset, r_info, addend = struct.unpack_from(endian + "QQq", data, offset)
            else:
                if offset + 16 > len(data):
                    break
                r_offset, r_info = struct.unpack_from(endian + "QQ", data, offset)
                addend = None
            symbol_index, relocation_type = r_info >> 32, r_info & 0xFFFFFFFF
            symbol = symbol_table[symbol_index] if symbol_index < len(symbol_table) else None
            target_section = sections[section["info"]]["name"] if section["info"] < len(sections) else None
            relocations.append({
                "section": section["name"], "target_section": target_section,
                "offset": r_offset, "type": _X86_64_RELOCATIONS.get(relocation_type, f"R_X86_64_{relocation_type}"),
                "type_value": relocation_type, "symbol_index": symbol_index,
                "symbol": symbol["name"] if symbol else None, "addend": addend,
            })
    return ParsedELF(tuple(sections), tuple(symbols), tuple(relocations))


def parse_elf_file(path: Path) -> ParsedELF:
    """Parse an ELF with pyelftools, falling back to the audited ELF64 reader.

    pyelftools is the supported BinOracle dependency. The fallback keeps the static
    privacy/unit tests useful before the optional dependency is installed; dynamic
    mode checks for pyelftools explicitly during prepare().
    """

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return parse_elf64(path.read_bytes())

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        sections: list[dict[str, Any]] = []
        section_indices: dict[int, int] = {}
        for index, section in enumerate(elf.iter_sections()):
            section_indices[id(section)] = index
            header = section.header
            kind = str(header["sh_type"])
            sections.append(
                {
                    "index": index,
                    "name": section.name,
                    "type": kind,
                    "type_value": kind,
                    "flags": int(header["sh_flags"]),
                    "address": int(header["sh_addr"]),
                    "offset": int(header["sh_offset"]),
                    "size": int(header["sh_size"]),
                    "link": int(header["sh_link"]),
                    "info": int(header["sh_info"]),
                    "alignment": int(header["sh_addralign"]),
                    "entry_size": int(header["sh_entsize"]),
                }
            )

        symbols: list[dict[str, Any]] = []
        symbols_by_table: dict[int, list[dict[str, Any]]] = {}
        for table_index, section in enumerate(elf.iter_sections()):
            if not isinstance(section, SymbolTableSection):
                continue
            table: list[dict[str, Any]] = []
            for number, symbol in enumerate(section.iter_symbols()):
                entry = symbol.entry
                shndx = entry["st_shndx"]
                section_index = int(shndx) if isinstance(shndx, int) else 0
                undefined = shndx == "SHN_UNDEF" or (
                    isinstance(shndx, int) and section_index == 0
                )
                if shndx == "SHN_COMMON":
                    section_name = "COMMON"
                elif 0 < section_index < len(sections):
                    section_name = sections[section_index]["name"]
                else:
                    section_name = None
                info = entry["st_info"]
                item = {
                    "table_section": table_index,
                    "index": number,
                    "name": symbol.name,
                    "binding": str(info["bind"]).removeprefix("STB_"),
                    "type": str(info["type"]).removeprefix("STT_"),
                    "visibility": str(entry["st_other"]["visibility"]),
                    "section_index": section_index,
                    "section": section_name,
                    "value": int(entry["st_value"]),
                    "size": int(entry["st_size"]),
                    "undefined": undefined,
                }
                table.append(item)
                symbols.append(item)
            symbols_by_table[table_index] = table

        relocations: list[dict[str, Any]] = []
        for relocation_index, section in enumerate(elf.iter_sections()):
            if not isinstance(section, RelocationSection):
                continue
            symbol_table_index = int(section.header["sh_link"])
            symbol_table = symbols_by_table.get(symbol_table_index, [])
            target_section_index = int(section.header["sh_info"])
            target_section = (
                sections[target_section_index]["name"]
                if target_section_index < len(sections)
                else None
            )
            for relocation in section.iter_relocations():
                entry = relocation.entry
                symbol_index = int(entry["r_info_sym"])
                relocation_type = int(entry["r_info_type"])
                symbol = symbol_table[symbol_index] if symbol_index < len(symbol_table) else None
                relocations.append(
                    {
                        "section": sections[relocation_index]["name"],
                        "target_section": target_section,
                        "offset": int(entry["r_offset"]),
                        "type": _X86_64_RELOCATIONS.get(
                            relocation_type, f"R_X86_64_{relocation_type}"
                        ),
                        "type_value": relocation_type,
                        "symbol_index": symbol_index,
                        "symbol": symbol["name"] if symbol else None,
                        "addend": int(entry["r_addend"])
                        if "r_addend" in entry
                        else None,
                    }
                )
    return ParsedELF(tuple(sections), tuple(symbols), tuple(relocations))
