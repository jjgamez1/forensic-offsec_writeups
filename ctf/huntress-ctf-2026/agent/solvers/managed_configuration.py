#!/usr/bin/env python3
"""Statically inspect the ELF and managed PE specimens in Table Manners."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import struct
import subprocess
import tempfile
import zlib
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    elf_machine_name,
    load_artifacts,
    questions_by_id,
    run_cli,
    validate_answer_format,
)
from agent.solvers.mangled import _members, analyze_cpp


def _tool(*args: str) -> str:
    try:
        result = subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=8
        )
    except FileNotFoundError as exc:
        raise SolverError(f"Required static tool is unavailable: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SolverError(f"Static inspection timed out: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise SolverError(f"{args[0]} could not inspect assigned bytes: {detail}") from exc
    return result.stdout


def _elf_symtab_names_raw(data: bytes, label: str) -> list[str]:
    """Read literal nonempty SHT_SYMTAB names via st_name and raw .strtab bytes."""
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise SolverError(f"{label}: ELF header is missing or truncated")
    elf_class, encoding = data[4], data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise SolverError(f"{label}: unsupported ELF class or byte order")
    if len(data) < (52 if elf_class == 1 else 64):
        raise SolverError(f"{label}: ELF header is truncated")
    endian = "<" if encoding == 1 else ">"
    if elf_class == 1:
        shoff = struct.unpack_from(endian + "I", data, 32)[0]
        shentsize = struct.unpack_from(endian + "H", data, 46)[0]
        shnum = struct.unpack_from(endian + "H", data, 48)[0]
        section_format = endian + "IIIIIIIIII"
        minimum_section_size = 40
        sym_minimum_size = 16
        sym_name_offset = 0
    else:
        shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        shentsize = struct.unpack_from(endian + "H", data, 58)[0]
        shnum = struct.unpack_from(endian + "H", data, 60)[0]
        section_format = endian + "IIQQQQIIQQ"
        minimum_section_size = 64
        sym_minimum_size = 24
        sym_name_offset = 0

    if shentsize < minimum_section_size or shoff > len(data):
        raise SolverError(f"{label}: ELF section-header table is malformed")
    if shnum == 0:
        if shoff + shentsize > len(data):
            raise SolverError(f"{label}: ELF extended section count is truncated")
        section_zero = struct.unpack_from(section_format, data, shoff)
        shnum = section_zero[5]  # sh_size in section header zero
    if shoff + shentsize * shnum > len(data):
        raise SolverError(f"{label}: ELF section-header table is truncated")

    sections = []
    for index in range(shnum):
        values = struct.unpack_from(section_format, data, shoff + index * shentsize)
        sections.append(
            {
                "name_offset": values[0],
                "type": values[1],
                "offset": values[4] if elf_class == 1 else values[4],
                "size": values[5] if elf_class == 1 else values[5],
                "link": values[6],
                "entry_size": values[9] if elf_class == 1 else values[9],
            }
        )

    def section_bytes(section: dict[str, int], description: str) -> bytes:
        start, size = section["offset"], section["size"]
        if start > len(data) or size > len(data) - start:
            raise SolverError(f"{label}: {description} section extends past EOF")
        return data[start : start + size]

    shstrndx_offset = 50 if elf_class == 1 else 62
    shstrndx = struct.unpack_from(endian + "H", data, shstrndx_offset)[0]
    if shstrndx == 0xFFFF:
        shstrndx = sections[0]["link"]
    if shstrndx >= len(sections):
        raise SolverError(f"{label}: ELF section-name string table index is invalid")
    section_names_data = section_bytes(sections[shstrndx], "section-name string table")

    def c_string(table: bytes, offset: int, description: str) -> bytes:
        if offset < 0 or offset >= len(table):
            raise SolverError(f"{label}: {description} string offset is invalid")
        end = table.find(b"\0", offset)
        if end < 0:
            raise SolverError(f"{label}: {description} string is unterminated")
        return table[offset:end]

    symbol_names: list[str] = []
    found_symtab = False
    for section in sections:
        if section["type"] != 2:  # SHT_SYMTAB; deliberately exclude SHT_DYNSYM.
            continue
        found_symtab = True
        link = section["link"]
        if link >= len(sections) or sections[link]["type"] != 3:
            raise SolverError(f"{label}: SHT_SYMTAB does not link to an SHT_STRTAB")
        linked_name = c_string(
            section_names_data,
            sections[link]["name_offset"],
            "section name",
        )
        if linked_name != b".strtab":
            raise SolverError(
                f"{label}: SHT_SYMTAB links to {linked_name!r}, expected .strtab"
            )
        strtab = section_bytes(sections[link], ".strtab")
        entry_size = section["entry_size"]
        if entry_size < sym_minimum_size or section["size"] % entry_size:
            raise SolverError(f"{label}: SHT_SYMTAB entry size is malformed")
        table = section_bytes(section, "SHT_SYMTAB")
        for entry_offset in range(0, len(table), entry_size):
            st_name = struct.unpack_from(
                endian + "I", table, entry_offset + sym_name_offset
            )[0]
            if st_name == 0:
                continue
            raw_name = c_string(strtab, st_name, "symbol")
            if raw_name:
                try:
                    symbol_names.append(raw_name.decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise SolverError(
                        f"{label}: raw .strtab symbol name is not UTF-8"
                    ) from exc
    # A stripped ELF may retain .dynsym while omitting SHT_SYMTAB entirely.
    # Questions that request SHT_SYMTAB entries then have an empty result;
    # do not substitute dynamic symbols for the absent symbol table.
    return symbol_names


def _elf_fields(data: bytes, label: str) -> tuple[dict[str, str], dict[str, str]]:
    with tempfile.TemporaryDirectory(prefix="ctf-table-manners-elf-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(label).name
        path.write_bytes(data)
        header = _tool("readelf", "-h", "-W", str(path))
        sections_out = _tool("readelf", "-SW", str(path))
        disassembly_out = _tool(
            "objdump", "-d", "-M", "intel", "--disassemble=recover_code", str(path)
        )

    def header_value(name: str) -> str:
        match = re.search(rf"^\s*{re.escape(name)}:\s*(.*?)\s*$", header, re.M)
        if not match:
            raise SolverError(f"{label}: ELF header is missing {name}")
        return match.group(1)

    section_names: list[str] = []
    for line in sections_out.splitlines():
        match = re.match(r"^\s*\[\s*(\d+)\]\s*(.*?)\s*$", line)
        if not match:
            continue
        number = int(match.group(1))
        rest = match.group(2)
        if number == 0:
            section_names.append("")
        else:
            name = rest.split(None, 1)[0] if rest.split() else ""
            section_names.append(name)

    symtab_names = _elf_symtab_names_raw(data, label)

    instructions: list[str] = []
    in_function = False
    for line in disassembly_out.splitlines():
        if re.match(r"^[0-9a-fA-F]+ <recover_code>:$", line.strip()):
            in_function = True
            continue
        if in_function and re.match(r"^[0-9a-fA-F]+ <[^>]+>:$", line.strip()):
            break
        if not in_function:
            continue
        instruction = re.match(
            r"^\s*[0-9a-fA-F]+:\s+(?:(?:[0-9a-fA-F]{2})\s+)+"
            r"([A-Za-z][A-Za-z0-9.]*(?:\s+.*)?)\s*$",
            line,
        )
        if instruction:
            instructions.append(instruction.group(1).strip())

    machine = elf_machine_name(header_value("Machine"))
    elf_class = header_value("Class")
    data_field = header_value("Data").lower()
    endianness = "little" if "little endian" in data_field else "big"
    type_match = re.match(r"([A-Z_]+)", header_value("Type"))
    if not type_match:
        raise SolverError(f"{label}: ELF e_type is not recognizable")
    elf_type = "ET_" + type_match.group(1)
    fields = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "elf_class": elf_class,
        "machine": machine,
        "section_names": json.dumps(section_names, separators=(",", ":")),
        "symbols": json.dumps(symtab_names, separators=(",", ":")),
        "disassembly": json.dumps(instructions, separators=(",", ":")),
        "elf_type": elf_type,
        "endianness": endianness,
    }
    evidence = {
        "sha256": "SHA-256 of the exact assigned ELF member bytes",
        "elf_class": "ELF header Class field",
        "machine": "ELF header Machine field",
        "section_names": "readelf section-header rows in table order, including the null entry's empty name",
        "symbols": "raw .strtab bytes addressed by st_name for each SHT_SYMTAB entry; dynamic symbols excluded",
        "disassembly": "objdump Intel disassembly of the recover_code FUNC symbol in execution order",
        "elf_type": "ELF header e_type field",
        "endianness": "ELF header EI_DATA field",
    }
    return fields, evidence


def _pe_sections(
    data: bytes, label: str
) -> tuple[int, list[tuple[str, int, int, int, int]], str]:
    if not data.startswith(b"MZ") or len(data) < 0x40:
        raise SolverError(f"{label}: assigned managed file lacks MZ magic bytes")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SolverError(f"{label}: PE signature is missing or truncated")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise SolverError(f"{label}: optional header is truncated")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        directories_offset = optional_offset + 96
        pe_kind = "PE32"
    elif magic == 0x20B:
        directories_offset = optional_offset + 112
        pe_kind = "PE32+"
    else:
        raise SolverError(f"{label}: unsupported PE optional-header magic {magic:#x}")
    cli_entry = directories_offset + 14 * 8
    if cli_entry + 8 > optional_offset + optional_size:
        raise SolverError(f"{label}: optional header has no CLR data-directory entry")
    cli_rva, cli_size = struct.unpack_from("<II", data, cli_entry)
    if not cli_rva or cli_size < 16:
        raise SolverError(f"{label}: PE has no CLR runtime directory")

    section_offset = optional_offset + optional_size
    sections = []
    for i in range(section_count):
        start = section_offset + i * 40
        if start + 40 > len(data):
            raise SolverError(f"{label}: PE section table is truncated")
        raw_name = data[start : start + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, start + 8
        )
        sections.append((name, virtual_address, virtual_size, raw_offset, raw_size))
    return cli_rva, sections, pe_kind


def _rva_to_offset(
    rva: int, sections: list[tuple[str, int, int, int, int]], label: str
) -> int:
    for _, virtual_address, virtual_size, raw_offset, raw_size in sections:
        extent = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + extent:
            offset = raw_offset + (rva - virtual_address)
            if offset >= raw_offset + raw_size:
                break
            return offset
    raise SolverError(f"{label}: RVA {rva:#x} does not map to file-backed section bytes")


def _metadata_version(data: bytes, label: str) -> tuple[str, str, str]:
    cli_rva, sections, pe_kind = _pe_sections(data, label)
    cli_offset = _rva_to_offset(cli_rva, sections, label)
    metadata_rva, metadata_size = struct.unpack_from("<II", data, cli_offset + 8)
    metadata_offset = _rva_to_offset(metadata_rva, sections, label)
    if metadata_size < 20 or data[metadata_offset : metadata_offset + 4] != b"BSJB":
        raise SolverError(f"{label}: CLR metadata root has no BSJB signature")
    version_length = struct.unpack_from("<I", data, metadata_offset + 12)[0]
    version_start = metadata_offset + 16
    version_end = version_start + version_length
    if version_length == 0 or version_end > metadata_offset + metadata_size:
        raise SolverError(f"{label}: CLR metadata version string is truncated")
    version = data[version_start:version_end].rstrip(b"\0").decode("ascii")
    machine = struct.unpack_from("<H", data, struct.unpack_from("<I", data, 0x3C)[0] + 4)[0]
    machine_names = {0x014C: "i386", 0x8664: "x86-64", 0x01C0: "ARM"}
    return version, machine_names.get(machine, f"0x{machine:04x}"), pe_kind


def _managed_config(data: bytes, label: str) -> tuple[dict[str, str], str]:
    _, sections, _ = _pe_sections(data, label)
    candidates = []
    for name, _, _, raw_offset, raw_size in sections:
        end = raw_offset + raw_size
        cursor = raw_offset
        while True:
            offset = data.find(b"HCFG", cursor, end)
            if offset < 0:
                break
            candidates.append(offset)
            cursor = offset + 1
    if len(candidates) != 1:
        raise SolverError(
            f"{label}: expected one HCFG header inside PE sections, found {len(candidates)}"
        )
    offset = candidates[0]
    if offset + 12 > len(data) or data[offset + 4] != 1:
        raise SolverError(f"{label}: HCFG header version or size is unsupported")
    key = data[offset + 5]
    payload_length = struct.unpack_from("<H", data, offset + 6)[0]
    encoded = data[offset + 12 : offset + 12 + payload_length]
    if len(encoded) != payload_length:
        raise SolverError(f"{label}: HCFG payload is truncated")
    decoded = bytes(value ^ key for value in encoded)
    try:
        config = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError(f"{label}: HCFG payload is not UTF-8 JSON") from exc
    if not isinstance(config, dict):
        raise SolverError(f"{label}: HCFG payload is not a JSON object")
    return {str(k): str(v) for k, v in config.items()}, (
        f"HCFG bytes at file offset {offset:#x}, XOR key {key:#04x}, "
        f"declared payload length {payload_length}; decoded JSON statically"
    )


def _pe_hcfg(data: bytes, label: str) -> tuple[dict[str, str], str, int, int]:
    """Read the HCFG record at byte zero of a PE section named exactly .hcfg."""
    if not data.startswith(b"MZ") or len(data) < 0x40:
        raise SolverError(f"{label}: PE DOS header is missing or truncated")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SolverError(f"{label}: PE signature is missing or truncated")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    if section_table + section_count * 40 > len(data):
        raise SolverError(f"{label}: PE section table is truncated")

    hcfg_sections = []
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0]
        if name != b".hcfg":
            continue
        _, _, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        if raw_offset > len(data) or raw_size > len(data) - raw_offset:
            raise SolverError(f"{label}: .hcfg section extends past EOF")
        hcfg_sections.append(data[raw_offset : raw_offset + raw_size])
    if len(hcfg_sections) != 1:
        raise SolverError(
            f"{label}: expected one PE section named exactly .hcfg, "
            f"found {len(hcfg_sections)}"
        )

    section = hcfg_sections[0]
    if len(section) < 12 or section[:4] != b"HCFG" or section[4] != 1:
        raise SolverError(f"{label}: .hcfg section has no supported HCFG header")
    key = section[5]
    payload_length = struct.unpack_from("<H", section, 6)[0]
    expected_crc = struct.unpack_from("<I", section, 8)[0]
    if payload_length > len(section) - 12:
        raise SolverError(f"{label}: .hcfg payload is truncated")
    decoded = bytes(value ^ key for value in section[12 : 12 + payload_length])
    actual_crc = zlib.crc32(decoded) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise SolverError(
            f"{label}: .hcfg CRC32 mismatch "
            f"(expected {expected_crc:#010x}, got {actual_crc:#010x})"
        )
    try:
        config = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError(f"{label}: .hcfg payload is not UTF-8 JSON") from exc
    if not isinstance(config, dict):
        raise SolverError(f"{label}: .hcfg payload is not a JSON object")
    return {str(k): str(v) for k, v in config.items()}, (
        "the PE section table's unique .hcfg section at section-relative byte "
        f"0; XOR key {key:#04x}, declared payload length {payload_length}; "
        "decoded JSON and verified CRC32"
    ), key, expected_crc


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    loaded = load_artifacts(artifact_paths)

    # Bind each downloaded ZIP to the delivery descriptor by content hash.  Names
    # such as evidence.zip repeat across Mastery deliveries, so path names cannot
    # identify the source archive safely.
    descriptors = start.get("artifacts")
    delivery_by_number: dict[int, tuple[pathlib.Path, bytes]] = {}
    if isinstance(descriptors, list) and descriptors:
        unused = list(loaded)
        for number, descriptor in enumerate(descriptors, start=1):
            expected_hash = (
                descriptor.get("sha256") if isinstance(descriptor, dict) else None
            )
            if not isinstance(expected_hash, str):
                raise SolverError(
                    f"Delivery {number} has no SHA-256 descriptor to bind its ZIP"
                )
            matches = [
                (path, data)
                for path, data in unused
                if hashlib.sha256(data).hexdigest() == expected_hash
            ]
            if len(matches) != 1:
                raise SolverError(
                    f"Delivery {number} ZIP does not match exactly one downloaded artifact"
                )
            delivery_by_number[number] = matches[0]
            unused.remove(matches[0])
        if unused:
            raise SolverError("A downloaded artifact is not listed in the start response")
    elif len(loaded) == 1:
        delivery_by_number[1] = loaded[0]
    else:
        raise SolverError("Cannot bind multiple artifact ZIPs to their deliveries")

    answer_delivery: dict[str, int] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = str(question.get("artifact", ""))
        delivery_match = re.search(r"\bdelivery\s+(\d+)\b", hint, re.I)
        scope, _ = parse_answer_id(answer_id)
        if delivery_match:
            delivery_number = int(delivery_match.group(1))
        elif scope and scope.startswith("set") and scope[3:].isdigit():
            delivery_number = int(scope[3:])
        elif len(delivery_by_number) == 1:
            delivery_number = next(iter(delivery_by_number))
        else:
            raise SolverError(
                f"{answer_id}: question does not identify its artifact delivery"
            )
        if delivery_number not in delivery_by_number:
            raise SolverError(
                f"{answer_id}: requested delivery {delivery_number} was not downloaded"
            )
        answer_delivery[answer_id] = delivery_number

    fields_by_delivery: dict[int, tuple[dict[str, str], dict[str, str]]] = {}

    def inspect_delivery(number: int) -> tuple[dict[str, str], dict[str, str]]:
        if number in fields_by_delivery:
            return fields_by_delivery[number]
        path, archive_data = delivery_by_number[number]
        members = _members(archive_data, path.name)
        if not members:
            raise SolverError(f"Delivery {number} evidence ZIP contains no members")

        by_day: dict[str, list[tuple[str, bytes]]] = {
            "d01": [],
            "d02": [],
            "d03": [],
        }
        for label, data in members:
            name = pathlib.PurePosixPath(label).name.lower()
            for day in by_day:
                if name.startswith(day + "--"):
                    by_day[day].append((label, data))
        for day in by_day:
            if not by_day[day]:
                raise SolverError(
                    f"Delivery {number} evidence ZIP has no hinted {day} specimen"
                )

        day1, d01_bytes = by_day["d01"][0]
        day2, d02_bytes = by_day["d02"][0]
        d03_dll_matches = [
            item for item in by_day["d03"] if item[0].lower().endswith(".dll")
        ]
        runtime_matches = [
            item
            for item in by_day["d03"]
            if item[0].lower().endswith(".runtimeconfig.json")
        ]
        if len(d03_dll_matches) != 1 or len(runtime_matches) != 1:
            raise SolverError(
                f"Delivery {number} has a missing or ambiguous Day 3 DLL/runtimeconfig pair"
            )
        d03_dll_label, d03_dll = d03_dll_matches[0]
        d03_runtime_label, d03_runtime = runtime_matches[0]

        d01_fields, d01_evidence = _elf_fields(d01_bytes, day1)
        if any(
            answer_delivery[answer_id] == number
            and parse_answer_id(answer_id)[1] == "d01_analysis_symbols"
            for answer_id in answer_ids
        ):
            all_d01_symbols: list[str] = []
            for day1_label, day1_member in by_day["d01"]:
                all_d01_symbols.extend(
                    _elf_symtab_names_raw(day1_member, day1_label)
                )
            d01_fields["symbols"] = json.dumps(
                all_d01_symbols, separators=(",", ":"), ensure_ascii=False
            )
            d01_evidence["symbols"] = (
                "every d01-- member from this delivery's ZIP in central-directory "
                "order; each SHT_SYMTAB entry in table order; nonempty names read "
                "from raw linked .strtab bytes via st_name, preserving duplicates"
            )
        if d02_bytes.startswith(b"MZ"):
            d02_config, d02_config_evidence, d02_key, d02_crc = _pe_hcfg(
                d02_bytes, day2
            )
            if not {"campaign", "domain", "mutex", "url"} <= set(d02_config):
                raise SolverError(
                    f"{day2}: decoded PE configuration lacks requested fields"
                )
            d02_fields = {
                "campaign": d02_config["campaign"],
                "domain": d02_config["domain"],
                "mutex": d02_config["mutex"],
                "url": d02_config["url"],
                "config_crc32": f"0x{d02_crc:08x}",
                "xor_key": f"0x{d02_key:02x}",
                "format": "PE",
            }
        else:
            d02_fields = analyze_cpp(d02_bytes, day2)
            if not d02_fields:
                raise SolverError(
                    f"{day2}: Day 2 specimen is neither a supported C++ ELF nor a PE"
                )
        pe_version, pe_machine, pe_kind = _metadata_version(d03_dll, d03_dll_label)
        config, config_evidence = _managed_config(d03_dll, d03_dll_label)
        if not {"campaign", "domain", "mutex"} <= set(config):
            raise SolverError(
                f"{d03_dll_label}: decoded configuration lacks requested fields"
            )

        field_values: dict[str, str] = {}
        evidence_values: dict[str, str] = {}
        for field, value in d01_fields.items():
            key = (
                "d01_artifact_sha256_1"
                if field == "sha256"
                else f"d01_analysis_{field}"
            )
            field_values[key] = value
            evidence_values[key] = f"{day1}: {d01_evidence[field]}"
        field_values.update(
            {
                "d02_artifact_sha256_1": hashlib.sha256(d02_bytes).hexdigest(),
                "d02_analysis_format": d02_fields["format"],
                "d02_analysis_config_campaign": d02_fields["campaign"],
                "d02_analysis_config_domain": d02_fields["domain"],
                "d02_analysis_config_mutex": d02_fields["mutex"],
                "d02_analysis_config_url": d02_fields["url"],
                "d02_analysis_config_crc32_hex": d02_fields["config_crc32"],
                "d02_analysis_xor_key_hex": d02_fields["xor_key"],
                "d03_artifact_sha256_1": hashlib.sha256(d03_dll).hexdigest(),
                "d03_artifact_sha256_2": hashlib.sha256(d03_runtime).hexdigest(),
                "d03_analysis_format": f"{pe_kind}_CLI",
                "d03_analysis_machine": pe_machine,
                "d03_analysis_metadata_version": pe_version,
                "d03_analysis_config_campaign": config["campaign"],
                "d03_analysis_config_domain": config["domain"],
                "d03_analysis_config_mutex": config["mutex"],
            }
        )
        for key in field_values:
            if key.startswith("d02_"):
                detail = (
                    d02_config_evidence
                    if d02_bytes.startswith(b"MZ")
                    else ".hcfg section parsed statically"
                )
                evidence_values[key] = f"{day2}: {detail}"
            elif key == "d03_artifact_sha256_1":
                evidence_values[key] = (
                    f"SHA-256 of exact assigned member {d03_dll_label}"
                )
            elif key == "d03_artifact_sha256_2":
                evidence_values[key] = (
                    f"SHA-256 of exact assigned member {d03_runtime_label}"
                )
            elif key == "d03_analysis_metadata_version":
                evidence_values[key] = (
                    f"{d03_dll_label}: CLR metadata-root version string"
                )
            elif key == "d03_analysis_machine":
                evidence_values[key] = f"{d03_dll_label}: PE/COFF Machine field"
            elif key == "d03_analysis_format":
                evidence_values[key] = (
                    f"{d03_dll_label}: PE32/PE32+ header and CLR directory"
                )
            elif key.startswith("d03_analysis_config_"):
                evidence_values[key] = f"{d03_dll_label}: {config_evidence}"
        fields_by_delivery[number] = (field_values, evidence_values)
        return fields_by_delivery[number]

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        delivery_number = answer_delivery[answer_id]
        field_values, evidence_values = inspect_delivery(delivery_number)
        _, field = parse_answer_id(answer_id)
        if field not in field_values:
            raise SolverError(f"{answer_id}: no static evidence mapping is defined")
        value = field_values[field]
        validate_answer_format(answer_id, value, questions[answer_id])
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Delivery {delivery_number}: {evidence_values[field]}"
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically inspect the Table Manners ELF and managed PE bundle")


if __name__ == "__main__":
    main()
