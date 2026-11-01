#!/usr/bin/env python3
"""Inspect the bundled ELF, PE/CLI, Go, and Rust specimens statically."""

from __future__ import annotations

import hashlib
import binascii
import json
import pathlib
import re
import struct
import subprocess
import tempfile
import zlib
import base64
import zipfile
import copy
from io import BytesIO
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    elf_machine_name,
    load_artifacts,
    questions_by_id,
    run_cli,
    validate_answer_format,
)
from agent.solvers.host_with_the_most import ARCHIVE_PASSWORD
from agent.solvers.managed_configuration import (
    _elf_fields,
    _metadata_version,
)
from agent.solvers.mangled import analyze_cpp, run_static_tool


def _readelf_machine(data: bytes, label: str) -> str:
    with tempfile.TemporaryDirectory(prefix="ctf-rust-shape-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(label).name
        path.write_bytes(data)
        try:
            result = subprocess.run(
                ["readelf", "-h", "-W", str(path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SolverError(f"{label}: readelf could not inspect the ELF header") from exc
    match = re.search(r"^\s*Machine:\s*(.*?)\s*$", result.stdout, re.MULTILINE)
    if not match:
        raise SolverError(f"{label}: ELF header has no Machine field")
    return elf_machine_name(match.group(1))


def _elf_machine_decimal(data: bytes, label: str) -> str:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise SolverError(f"{label}: ELF header is missing or truncated")
    endian = {1: "<", 2: ">"}.get(data[5])
    if endian is None:
        raise SolverError(f"{label}: ELF header has an unsupported byte order")
    return str(struct.unpack_from(endian + "H", data, 18)[0])


def _read_uleb(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = shift = 0
    while offset < end and shift <= 35:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise SolverError("Malformed WebAssembly LEB128 integer")


def _skip_sleb(data: bytes, offset: int, end: int) -> int:
    shift = 0
    while offset < end and shift <= 70:
        byte = data[offset]
        offset += 1
        if byte < 0x80:
            return offset
        shift += 7
    raise SolverError("Malformed WebAssembly signed LEB128 integer")


def _wasm_init_expr_end(data: bytes, offset: int, end: int) -> int:
    while offset < end:
        opcode = data[offset]
        offset += 1
        if opcode == 0x0B:
            return offset
        if opcode == 0x41:
            offset = _skip_sleb(data, offset, end)
        elif opcode == 0x42:
            offset = _skip_sleb(data, offset, end)
        elif opcode == 0x23:
            _value, offset = _read_uleb(data, offset, end)
        elif opcode == 0xD0:
            if offset >= end:
                break
            offset += 1
        else:
            raise SolverError(
                f"Unsupported opcode 0x{opcode:02x} in WebAssembly data offset expression"
            )
    raise SolverError("Unterminated WebAssembly data offset expression")


def _wasm_data_segments(data: bytes, label: str) -> list[bytes]:
    if len(data) < 8 or data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise SolverError(f"{label}: invalid WebAssembly version-1 header")
    segments: list[bytes] = []
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        section_size, offset = _read_uleb(data, offset, len(data))
        section_end = offset + section_size
        if section_end > len(data):
            raise SolverError(f"{label}: WebAssembly section exceeds the module")
        if section_id == 11:
            count, cursor = _read_uleb(data, offset, section_end)
            for _ in range(count):
                flags, cursor = _read_uleb(data, cursor, section_end)
                if flags == 0:
                    cursor = _wasm_init_expr_end(data, cursor, section_end)
                elif flags == 1:
                    pass
                elif flags == 2:
                    _memory_index, cursor = _read_uleb(data, cursor, section_end)
                    cursor = _wasm_init_expr_end(data, cursor, section_end)
                else:
                    raise SolverError(f"{label}: unsupported WebAssembly data segment flags {flags}")
                byte_count, cursor = _read_uleb(data, cursor, section_end)
                segment_end = cursor + byte_count
                if segment_end > section_end:
                    raise SolverError(f"{label}: WebAssembly data segment is truncated")
                segments.append(data[cursor:segment_end])
                cursor = segment_end
            if cursor != section_end:
                raise SolverError(f"{label}: trailing bytes in WebAssembly data section")
        offset = section_end
    return segments


def _format_machine(data: bytes, label: str) -> tuple[str, str]:
    if data.startswith(b"\x7fELF"):
        return "elf", _readelf_machine(data, label)
    if data.startswith(b"MZ"):
        fmt, machine, _sections = _pe_header(data, label)
        try:
            _version, _machine, kind = _metadata_version(data, label)
        except SolverError:
            kind = ""
        return ("pe_cli" if kind else "pe"), machine
    if data.startswith(b"\x00asm\x01\x00\x00\x00"):
        return "wasm", "wasm32"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(BytesIO(data)) as archive:
                has_classes = any(name.endswith(".class") for name in archive.namelist())
        except zipfile.BadZipFile:
            has_classes = False
        if has_classes:
            return "jar", "unknown"
    if data.startswith(b"NEKO"):
        return "neko_bytecode", "unknown"
    raise SolverError(f"{label}: unsupported binary container")


def _overlay_hcfg(data: bytes, label: str, marker: bytes) -> tuple[int, int, bytes, int]:
    overlay_offset = data.rfind(marker)
    if overlay_offset < 0:
        raise SolverError(f"{label}: final {marker.decode('ascii')} overlay is missing")
    if marker == b"PK19":
        if overlay_offset + 44 > len(data):
            raise SolverError(f"{label}: PK19 overlay header is truncated")
        key1, key2 = data[overlay_offset + 5], data[overlay_offset + 6]
        packed_length = struct.unpack_from("<I", data, overlay_offset + 8)[0]
        digest = data[overlay_offset + 12 : overlay_offset + 44]
        start = overlay_offset + 44
        end = start + packed_length
        if end != len(data):
            raise SolverError(f"{label}: PK19 packed length does not match the final overlay")
        packed = data[start:end]
        unpacked = bytes(
            (((byte ^ key2) >> 3) | ((byte ^ key2) << 5) & 0xFF) ^ key1
            for byte in packed
        )
        if hashlib.sha256(unpacked).digest() != digest:
            raise SolverError(f"{label}: PK19 unpacked SHA-256 does not match")
        if not unpacked.startswith(b"HCFG"):
            raise SolverError(f"{label}: PK19 payload does not begin with HCFG")
        return overlay_offset, len(data) - overlay_offset, unpacked, overlay_offset
    if marker == b"RS20":
        if overlay_offset + 48 > len(data):
            raise SolverError(f"{label}: RS20 overlay header is truncated")
        resource_size = struct.unpack_from("<I", data, overlay_offset + 8)[0]
        scratch_size = struct.unpack_from("<H", data, overlay_offset + 12)[0]
        scratch_digest = data[overlay_offset + 16 : overlay_offset + 48]
        resource_start = overlay_offset + 48
        resource_end = resource_start + resource_size
        end = resource_end + scratch_size
        if end != len(data):
            raise SolverError(f"{label}: RS20 resource/scratch lengths do not match the final overlay")
        resource, scratch = data[resource_start:resource_end], data[resource_end:end]
        if hashlib.sha256(scratch).digest() != scratch_digest:
            raise SolverError(f"{label}: RS20 scratch SHA-256 does not match")
        if not resource.startswith(b"HCFG"):
            raise SolverError(f"{label}: RS20 resource does not begin with HCFG")
        return overlay_offset, resource_size, resource, overlay_offset
    raise SolverError(f"{label}: unsupported overlay type")


def _pe_discovery_engine_predicates(data: bytes, label: str) -> tuple[str, str]:
    """Evaluate the returned C++ symbol predicates from the PE symbol table."""
    if not data.startswith(b"MZ"):
        raise SolverError(f"{label}: expected MZ bytes for PE symbol inspection")
    with tempfile.TemporaryDirectory(prefix="ctf-nim-pe-symbols-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(label).name
        path.write_bytes(data)
        output = run_static_tool("objdump", "-t", str(path))
    symbols: list[str] = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) >= 2 and re.search(r"\b0x[0-9a-fA-F]+\b", line):
            symbols.append(columns[-1])
    has_typeinfo = any(
        re.search(r"ZTI.*DiscoveryEngine", symbol) for symbol in symbols
    )
    has_vtable = any(
        re.search(r"ZTV.*DiscoveryEngine", symbol) for symbol in symbols
    )
    return ("true" if has_typeinfo else "false", "true" if has_vtable else "false")


def _runtime_members(
    paths: list[pathlib.Path],
    loaded: list[tuple[pathlib.Path, bytes]] | None = None,
) -> tuple[list[tuple[str, bytes]], list[list[tuple[str, bytes]]]]:
    """Expand assigned ZIPs while keeping JAR files intact as answerable specimens."""
    if loaded is None:
        loaded = load_artifacts(paths)
    by_artifact: list[list[tuple[str, bytes]]] = []

    def expand(data: bytes, label: str, depth: int = 0) -> list[tuple[str, bytes]]:
        if depth > 8:
            raise SolverError("Nested ZIP depth exceeds the static inspection limit")
        if not data.startswith(b"PK\x03\x04"):
            return [(label, data)]
        try:
            with zipfile.ZipFile(BytesIO(data)) as probe:
                infos = [info for info in probe.infolist() if not info.is_dir()]
                encrypted = any(info.flag_bits & 1 for info in infos)
        except zipfile.BadZipFile:
            return [(label, data)]
        if encrypted:
            try:
                import pyzipper

                with pyzipper.AESZipFile(BytesIO(data)) as archive:
                    archive.pwd = ARCHIVE_PASSWORD.encode("utf-8")
                    entries = [
                        (info.filename, archive.read(info))
                        for info in archive.infolist()
                        if not info.is_dir()
                    ]
            except (ImportError, OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
                raise SolverError(f"Could not read assigned AES ZIP {label}") from exc
        else:
            with zipfile.ZipFile(BytesIO(data)) as archive:
                entries = [
                    (info.filename, archive.read(info))
                    for info in archive.infolist()
                    if not info.is_dir()
                ]
        members: list[tuple[str, bytes]] = []
        for name, payload in entries:
            member_label = f"{label}/{name}"
            if pathlib.PurePosixPath(name).suffix.lower() == ".jar":
                members.append((member_label, payload))
            else:
                members.extend(expand(payload, member_label, depth + 1))
        return members

    for path, data in loaded:
        by_artifact.append(expand(data, path.name))
    return [member for delivery in by_artifact for member in delivery], by_artifact


def _crc_valid_hcfg(data: bytes, label: str) -> list[tuple[int, int, dict[str, Any]]]:
    valid: list[tuple[int, int, dict[str, Any]]] = []
    offset = 0
    while True:
        offset = data.find(b"HCFG", offset)
        if offset < 0:
            break
        if offset + 12 <= len(data):
            version = data[offset + 4]
            key = data[offset + 5]
            length = struct.unpack_from("<H", data, offset + 6)[0]
            expected_crc = struct.unpack_from("<I", data, offset + 8)[0]
            end = offset + 12 + length
            if version == 1 and end <= len(data):
                decoded = bytes(value ^ key for value in data[offset + 12 : end])
                if zlib.crc32(decoded) & 0xFFFFFFFF == expected_crc:
                    try:
                        config = json.loads(decoded.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        config = None
                    if isinstance(config, dict):
                        valid.append((offset, key, config))
        offset += 1
    if not valid:
        raise SolverError(f"{label}: no bounds-checked CRC32-valid HCFG JSON record was found")
    return valid


def _base64_hcfg(
    data: bytes, label: str
) -> tuple[int, int, dict[str, Any], int, int]:
    """Find the first CRC-valid HCFG record beginning a decoded Base64 run."""
    for match in re.finditer(rb"[A-Za-z0-9+/]{100,}={0,2}", data):
        try:
            decoded = base64.b64decode(match.group(0), validate=True)
        except (ValueError, binascii.Error):
            continue
        if not decoded.startswith(b"HCFG"):
            continue
        try:
            records = _crc_valid_hcfg(decoded, label)
        except SolverError:
            continue
        first = next((record for record in records if record[0] == 0), None)
        if first is not None:
            offset, key, config = first
            return (
                offset,
                key,
                config,
                struct.unpack_from("<I", decoded, offset + 8)[0],
                match.start(),
            )
    raise SolverError(f"{label}: no Base64 run begins with a CRC32-valid HCFG record")


def _class_utf8_constants(data: bytes, label: str) -> list[str]:
    """Read UTF-8 entries in a JVM class constant pool without loading the class."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise SolverError(f"{label}: invalid or truncated Java class file")
    count = struct.unpack_from(">H", data, 8)[0]
    position = 10
    constants: list[str] = []
    index = 1
    while index < count:
        if position >= len(data):
            raise SolverError(f"{label}: truncated Java constant pool")
        tag = data[position]
        position += 1
        if tag == 1:  # CONSTANT_Utf8
            if position + 2 > len(data):
                raise SolverError(f"{label}: truncated Java UTF-8 constant")
            length = struct.unpack_from(">H", data, position)[0]
            position += 2
            end = position + length
            if end > len(data):
                raise SolverError(f"{label}: Java UTF-8 constant exceeds the class file")
            # Modified UTF-8 may contain encoded NULs or surrogate pairs. The
            # caller only searches these constants for ASCII Base64 runs, so
            # Latin-1 preserves every source byte while keeping that scan exact.
            constants.append(data[position:end].decode("latin-1"))
            position = end
        elif tag in {3, 4}:  # Integer, Float
            position += 4
        elif tag in {5, 6}:  # Long, Double occupy two pool indexes
            position += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:  # Class, String, MethodType, Module, Package
            position += 2
        elif tag in {9, 10, 11, 12, 17, 18}:  # refs, NameAndType, Dynamic
            position += 4
        elif tag == 15:  # MethodHandle
            position += 3
        else:
            raise SolverError(f"{label}: unsupported Java constant-pool tag {tag}")
        if position > len(data):
            raise SolverError(f"{label}: constant-pool entry exceeds the class file")
        index += 1
    return constants


def _jar_main_hcfg(
    data: bytes, label: str
) -> tuple[int, int, dict[str, Any], str, bytes]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            manifests = [
                info for info in archive.infolist()
                if info.filename.upper() == "META-INF/MANIFEST.MF"
            ]
            if len(manifests) != 1:
                raise SolverError(f"{label}: JAR has no unique manifest")
            manifest = archive.read(manifests[0]).decode("utf-8", errors="strict")
            unfolded = re.sub(r"\r?\n ", "", manifest)
            main_match = re.search(
                r"(?im)^Main-Class:\s*([^\r\n]+)", unfolded
            )
            if main_match is None:
                raise SolverError(f"{label}: JAR manifest has no Main-Class")
            class_name = main_match.group(1).strip().replace(".", "/") + ".class"
            class_matches = [
                info for info in archive.infolist()
                if info.filename == class_name
            ]
            if len(class_matches) != 1:
                raise SolverError(f"{label}: Main-Class entry {class_name!r} is missing or ambiguous")
            class_data = archive.read(class_matches[0])
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError) as exc:
        raise SolverError(f"{label}: assigned JAR could not be read statically") from exc

    for constant_index, value in enumerate(_class_utf8_constants(class_data, label), 1):
        if len(value) < 80 or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            continue
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            continue
        try:
            records = _crc_valid_hcfg(decoded, label)
        except SolverError:
            continue
        if records:
            offset, key, config = records[0]
            length = struct.unpack_from("<H", decoded, offset + 6)[0]
            record = decoded[offset : offset + 12 + length]
            return (
                offset,
                key,
                config,
                f"Main-Class constant-pool UTF-8 entry {constant_index}",
                record,
            )
    raise SolverError(f"{label}: no Base64 UTF-8 constant contains a CRC32-valid HCFG record")


def _jar_any_class_hcfg(
    data: bytes, label: str
) -> tuple[int, int, dict[str, Any], bytes, str]:
    """Find the first valid HCFG carried by any class UTF-8 constant in ZIP order."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            class_infos = [
                info for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".class")
            ]
            for info in class_infos:
                class_data = archive.read(info)
                constants = _class_utf8_constants(
                    class_data, f"{label}/{info.filename}"
                )
                for constant_index, value in enumerate(constants, 1):
                    if len(value) < 80 or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
                        continue
                    try:
                        decoded = base64.b64decode(value, validate=True)
                    except (ValueError, binascii.Error):
                        continue
                    try:
                        records = _crc_valid_hcfg(
                            decoded, f"{label}/{info.filename}"
                        )
                    except SolverError:
                        continue
                    offset, key, config = records[0]
                    length = struct.unpack_from("<H", decoded, offset + 6)[0]
                    raw_payload = bytes(
                        byte ^ key
                        for byte in decoded[offset + 12 : offset + 12 + length]
                    )
                    return (
                        offset,
                        key,
                        config,
                        raw_payload,
                        f"{info.filename} UTF-8 constant {constant_index}",
                    )
    except (zipfile.BadZipFile, OSError) as exc:
        raise SolverError(f"{label}: assigned JAR could not be read statically") from exc
    raise SolverError(
        f"{label}: no class UTF-8 constant contains a CRC32-valid HCFG record"
    )


def _pe_header(
    data: bytes, label: str
) -> tuple[str, str, list[tuple[str, int, int]]]:
    """Read a PE/COFF machine, container, and file-backed section table."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise SolverError(f"{label}: assigned file lacks a complete MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SolverError(f"{label}: PE signature is missing or truncated")
    machine_code, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data) or optional_size < 2:
        raise SolverError(f"{label}: PE optional header is truncated")
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if optional_magic == 0x10B:
        pe_format = "PE32"
    elif optional_magic == 0x20B:
        pe_format = "PE32+"
    else:
        raise SolverError(f"{label}: unsupported PE optional-header magic")
    machine_names = {
        0x014C: "i386",
        0x0166: "MIPS",
        0x01C0: "ARM",
        0x01C4: "ARMNT",
        0x01F0: "PowerPC",
        0x8664: "x86-64",
        0xAA64: "AArch64",
    }
    machine = machine_names.get(machine_code, f"0x{machine_code:04x}")
    section_table = optional_offset + optional_size
    if section_table + section_count * 40 > len(data):
        raise SolverError(f"{label}: PE section table is truncated")
    sections: list[tuple[str, int, int]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: PE section name is not ASCII") from exc
        raw_size, raw_offset = struct.unpack_from("<II", data, offset + 16)
        if raw_offset + raw_size > len(data):
            raise SolverError(f"{label}: PE section {name!r} exceeds the file")
        sections.append((name, raw_offset, raw_size))
    return pe_format, machine, sections


def _decode_hcfg_record(
    record: bytes, label: str, file_offset: int
) -> tuple[int, dict[str, Any]]:
    if len(record) < 12 or record[:4] != b"HCFG" or record[4] != 1:
        raise SolverError(f"{label}: .hcfg section does not begin with a supported HCFG record")
    key = record[5]
    length = struct.unpack_from("<H", record, 6)[0]
    if 12 + length > len(record):
        raise SolverError(f"{label}: HCFG payload exceeds its .hcfg section")
    expected_crc = struct.unpack_from("<I", record, 8)[0]
    decoded = bytes(value ^ key for value in record[12 : 12 + length])
    if zlib.crc32(decoded) & 0xFFFFFFFF != expected_crc:
        raise SolverError(f"{label}: HCFG payload CRC32 does not validate")
    try:
        config = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError(f"{label}: HCFG payload is not UTF-8 JSON") from exc
    if not isinstance(config, dict):
        raise SolverError(f"{label}: decoded HCFG JSON is not an object")
    return key, config


def _elf_literal_section_fields(data: bytes, label: str) -> tuple[list[str], list[str]]:
    """Read section and symbol names straight from ELF string tables."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise SolverError(f"{label}: truncated or invalid ELF header")
    elf_class, elf_data = data[4], data[5]
    if elf_class not in {1, 2} or elf_data not in {1, 2}:
        raise SolverError(f"{label}: unsupported ELF class or byte order")
    endian = "<" if elf_data == 1 else ">"
    if elf_class == 2:
        if len(data) < 64:
            raise SolverError(f"{label}: truncated ELF64 header")
        shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        minimum_entry_size = 64
    else:
        shoff = struct.unpack_from(endian + "I", data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 46)
        minimum_entry_size = 40
    if (
        shentsize < minimum_entry_size
        or shnum == 0
        or shstrndx >= shnum
        or shoff + shentsize * shnum > len(data)
    ):
        raise SolverError(f"{label}: invalid ELF section-header table")

    sections = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if elf_class == 2:
            name_offset, section_type = struct.unpack_from(endian + "II", data, base)
            section_offset, section_size = struct.unpack_from(endian + "QQ", data, base + 24)
            link = struct.unpack_from(endian + "I", data, base + 40)[0]
            entry_size = struct.unpack_from(endian + "Q", data, base + 56)[0]
        else:
            name_offset, section_type = struct.unpack_from(endian + "II", data, base)
            section_offset, section_size = struct.unpack_from(endian + "II", data, base + 16)
            link = struct.unpack_from(endian + "I", data, base + 24)[0]
            entry_size = struct.unpack_from(endian + "I", data, base + 36)[0]
        # SHT_NOBITS (for example .bss) reserves memory without occupying
        # bytes in the file, so its logical size may extend past EOF.
        if section_type != 8 and section_offset + section_size > len(data):
            raise SolverError(f"{label}: section {index} exceeds the file")
        sections.append(
            (name_offset, section_type, section_offset, section_size, link, entry_size)
        )

    shstr = sections[shstrndx]
    shstr_bytes = data[shstr[2] : shstr[2] + shstr[3]]

    def read_name(table: bytes, offset: int) -> str:
        if offset >= len(table):
            raise SolverError(f"{label}: string-table name offset is out of range")
        end = table.find(b"\0", offset)
        if end < 0:
            raise SolverError(f"{label}: unterminated ELF string-table name")
        try:
            return table[offset:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: ELF string-table name is not UTF-8") from exc

    section_names = [read_name(shstr_bytes, section[0]) for section in sections]
    symbol_names: list[str] = []
    for _, section_type, offset, size, link, entry_size in sections:
        if section_type != 2:  # SHT_SYMTAB
            continue
        if link >= len(sections) or entry_size < (24 if elf_class == 2 else 16):
            raise SolverError(f"{label}: malformed SHT_SYMTAB header")
        string_section = sections[link]
        strings = data[string_section[2] : string_section[2] + string_section[3]]
        if size % entry_size:
            raise SolverError(f"{label}: SHT_SYMTAB has a partial entry")
        for entry in range(offset, offset + size, entry_size):
            name_offset = struct.unpack_from(endian + "I", data, entry)[0]
            if name_offset:
                symbol_names.append(read_name(strings, name_offset))
    return section_names, symbol_names


def _elf_marker_and_recover_code(data: bytes, label: str) -> tuple[str, str]:
    """Read the literal .huntress bytes and recover_code FUNC symbol from ELF tables."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise SolverError(f"{label}: truncated or invalid ELF header")
    elf_class, elf_data = data[4], data[5]
    if elf_class not in {1, 2} or elf_data not in {1, 2}:
        raise SolverError(f"{label}: unsupported ELF class or byte order")
    endian = "<" if elf_data == 1 else ">"
    if elf_class == 2:
        if len(data) < 64:
            raise SolverError(f"{label}: truncated ELF64 header")
        shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        minimum_sh_size, minimum_sym_size = 64, 24
    else:
        shoff = struct.unpack_from(endian + "I", data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 46)
        minimum_sh_size, minimum_sym_size = 40, 16
    if (
        shentsize < minimum_sh_size
        or shnum == 0
        or shstrndx >= shnum
        or shoff + shentsize * shnum > len(data)
    ):
        raise SolverError(f"{label}: invalid ELF section-header table")

    sections: list[dict[str, int]] = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if elf_class == 2:
            name_offset, section_type = struct.unpack_from(endian + "II", data, base)
            address, offset, size = struct.unpack_from(endian + "QQQ", data, base + 16)
            link = struct.unpack_from(endian + "I", data, base + 40)[0]
            entry_size = struct.unpack_from(endian + "Q", data, base + 56)[0]
        else:
            name_offset, section_type = struct.unpack_from(endian + "II", data, base)
            address, offset, size = struct.unpack_from(endian + "III", data, base + 12)
            link = struct.unpack_from(endian + "I", data, base + 24)[0]
            entry_size = struct.unpack_from(endian + "I", data, base + 36)[0]
        if section_type != 8 and offset + size > len(data):
            raise SolverError(f"{label}: ELF section {index} exceeds the file")
        sections.append(
            {
                "name_offset": name_offset,
                "type": section_type,
                "address": address,
                "offset": offset,
                "size": size,
                "link": link,
                "entry_size": entry_size,
            }
        )

    shstr = sections[shstrndx]
    names = data[shstr["offset"] : shstr["offset"] + shstr["size"]]

    def cstring(table: bytes, offset: int, what: str) -> bytes:
        if offset >= len(table):
            raise SolverError(f"{label}: {what} string offset is out of range")
        end = table.find(b"\0", offset)
        if end < 0:
            raise SolverError(f"{label}: unterminated {what} string")
        return table[offset:end]

    section_names = [
        cstring(names, section["name_offset"], "section").decode("utf-8")
        for section in sections
    ]
    marker_sections = [
        (section, name)
        for section, name in zip(sections, section_names)
        if name == ".huntress"
    ]
    if len(marker_sections) != 1:
        raise SolverError(
            f"{label}: expected one .huntress section, found {len(marker_sections)}"
        )
    marker_section = marker_sections[0][0]
    marker_bytes = data[
        marker_section["offset"] : marker_section["offset"] + marker_section["size"]
    ].rstrip(b"\0")
    try:
        marker = marker_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: .huntress section is not UTF-8") from exc

    symbol_matches: list[tuple[int, int, int]] = []
    for section in sections:
        if section["type"] != 2:  # SHT_SYMTAB, deliberately excluding .dynsym.
            continue
        entry_size = section["entry_size"]
        if section["link"] >= len(sections) or entry_size < minimum_sym_size:
            raise SolverError(f"{label}: malformed SHT_SYMTAB header")
        strings_section = sections[section["link"]]
        strings = data[
            strings_section["offset"] : strings_section["offset"] + strings_section["size"]
        ]
        if section["size"] % entry_size:
            raise SolverError(f"{label}: SHT_SYMTAB has a partial entry")
        for entry in range(
            section["offset"], section["offset"] + section["size"], entry_size
        ):
            if elf_class == 2:
                name_offset = struct.unpack_from(endian + "I", data, entry)[0]
                symbol_type = data[entry + 4] & 0x0F
                symbol_section = struct.unpack_from(endian + "H", data, entry + 6)[0]
                value, size = struct.unpack_from(endian + "QQ", data, entry + 8)
            else:
                name_offset = struct.unpack_from(endian + "I", data, entry)[0]
                value, size = struct.unpack_from(endian + "II", data, entry + 4)
                symbol_type = data[entry + 12] & 0x0F
                symbol_section = struct.unpack_from(endian + "H", data, entry + 14)[0]
            if (
                name_offset
                and symbol_type == 2  # STT_FUNC
                and cstring(strings, name_offset, "symbol") == b"recover_code"
            ):
                symbol_matches.append((symbol_section, value, size))
    if not symbol_matches:
        return marker, "none"
    if len(symbol_matches) != 1:
        raise SolverError(f"{label}: recover_code has multiple SHT_SYMTAB FUNC symbols")

    symbol_section, value, size = symbol_matches[0]
    if symbol_section >= len(sections):
        raise SolverError(f"{label}: recover_code section index is out of range")
    owner = sections[symbol_section]
    relative = value - owner["address"]
    if relative < 0 or relative + size > owner["size"]:
        raise SolverError(f"{label}: recover_code symbol exceeds its ELF section")
    code = data[owner["offset"] + relative : owner["offset"] + relative + size]
    if len(code) != 6 or code[0] != 0xB8 or code[5] != 0xC3:
        raise SolverError(
            f"{label}: recover_code bytes are not exactly mov eax, imm32; ret"
        )
    immediate = struct.unpack_from(endian + "I", code, 1)[0]
    return marker, str(immediate)


def _pe_coff_symbol_names(data: bytes, label: str) -> list[str]:
    """Read primary COFF symbols in raw table order, retaining section symbols."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise SolverError(f"{label}: invalid or truncated PE DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SolverError(f"{label}: invalid PE signature or truncated COFF header")
    symbol_offset, symbol_count = struct.unpack_from("<II", data, pe_offset + 12)
    if symbol_count == 0:
        return []
    table_end = symbol_offset + symbol_count * 18
    if symbol_offset < pe_offset + 24 or table_end + 4 > len(data):
        raise SolverError(f"{label}: COFF symbol table exceeds the file")
    string_size = struct.unpack_from("<I", data, table_end)[0]
    if string_size < 4 or table_end + string_size > len(data):
        raise SolverError(f"{label}: invalid COFF string table")
    strings = data[table_end : table_end + string_size]
    result: list[str] = []
    index = 0
    while index < symbol_count:
        entry = symbol_offset + index * 18
        name_bytes = data[entry : entry + 8]
        if name_bytes[:4] == b"\0\0\0\0":
            name_offset = struct.unpack_from("<I", name_bytes, 4)[0]
            if name_offset < 4 or name_offset >= len(strings):
                raise SolverError(f"{label}: COFF long-name offset is out of range")
            name_end = strings.find(b"\0", name_offset)
            if name_end < 0:
                raise SolverError(f"{label}: unterminated COFF long symbol name")
            raw_name = strings[name_offset:name_end]
        else:
            raw_name = name_bytes.split(b"\0", 1)[0]
        if raw_name:
            try:
                result.append(raw_name.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise SolverError(f"{label}: COFF symbol name is not UTF-8") from exc
        auxiliary_count = data[entry + 17]
        index += 1 + auxiliary_count
    if index != symbol_count:
        raise SolverError(f"{label}: COFF auxiliary symbol count overruns the table")
    return result


def _pe_section_names(data: bytes, label: str) -> list[str]:
    """Read PE section names, resolving slash-decimal names via COFF strings."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise SolverError(f"{label}: invalid or truncated PE DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SolverError(f"{label}: invalid PE signature or truncated COFF header")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    symbol_offset, symbol_count = struct.unpack_from("<II", data, pe_offset + 12)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    table_end = section_table + section_count * 40
    if table_end > len(data):
        raise SolverError(f"{label}: PE section table exceeds the file")
    strings = b""
    if symbol_offset and symbol_count:
        string_table = symbol_offset + symbol_count * 18
        if string_table + 4 > len(data):
            raise SolverError(f"{label}: COFF string table is truncated")
        string_size = struct.unpack_from("<I", data, string_table)[0]
        if string_size < 4 or string_table + string_size > len(data):
            raise SolverError(f"{label}: invalid COFF string table")
        strings = data[string_table : string_table + string_size]
    names: list[str] = []
    for index in range(section_count):
        raw = data[section_table + index * 40 : section_table + index * 40 + 8]
        raw = raw.split(b"\0", 1)[0]
        if raw.startswith(b"/") and raw[1:].isdigit():
            if not strings:
                raise SolverError(f"{label}: long PE section name has no COFF string table")
            name_offset = int(raw[1:])
            if name_offset < 4 or name_offset >= len(strings):
                raise SolverError(f"{label}: PE section-name offset is out of range")
            name_end = strings.find(b"\0", name_offset)
            if name_end < 0:
                raise SolverError(f"{label}: unterminated PE section name")
            raw = strings[name_offset:name_end]
        try:
            names.append(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: PE section name is not UTF-8") from exc
    return names


def _jar_main_class_details(data: bytes, label: str) -> tuple[list[str], int, int, bool]:
    """Read Main-Class method table and coroutine marker without loading Java code."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            manifests = [
                info
                for info in archive.infolist()
                if info.filename.upper() == "META-INF/MANIFEST.MF"
            ]
            if len(manifests) != 1:
                raise SolverError(f"{label}: JAR has no unique manifest")
            manifest = archive.read(manifests[0]).decode("utf-8", errors="strict")
            unfolded = re.sub(r"\r?\n ", "", manifest)
            main = re.search(r"(?im)^Main-Class:\s*([^\r\n]+)", unfolded)
            if main is None:
                raise SolverError(f"{label}: JAR manifest has no Main-Class")
            class_name = main.group(1).strip().replace(".", "/") + ".class"
            matches = [info for info in archive.infolist() if info.filename == class_name]
            if len(matches) != 1:
                raise SolverError(f"{label}: Main-Class {class_name!r} is missing or ambiguous")
            class_data = archive.read(matches[0])
            has_coroutines = any(
                info.filename == "kotlin/coroutines/Continuation.class"
                for info in archive.infolist()
            )
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError) as exc:
        raise SolverError(f"{label}: assigned JAR could not be read statically") from exc

    if len(class_data) < 10 or class_data[:4] != b"\xca\xfe\xba\xbe":
        raise SolverError(f"{label}: invalid or truncated Main-Class file")
    cp_count = struct.unpack_from(">H", class_data, 8)[0]
    cp: list[str | None] = [None] * cp_count
    pos = 10
    index = 1
    while index < cp_count:
        if pos >= len(class_data):
            raise SolverError(f"{label}: truncated Main-Class constant pool")
        tag = class_data[pos]
        pos += 1
        if tag == 1:
            if pos + 2 > len(class_data):
                raise SolverError(f"{label}: truncated Main-Class UTF-8 entry")
            size = struct.unpack_from(">H", class_data, pos)[0]
            pos += 2
            end = pos + size
            if end > len(class_data):
                raise SolverError(f"{label}: Main-Class UTF-8 entry exceeds class file")
            cp[index] = class_data[pos:end].decode("utf-8", errors="replace")
            pos = end
        elif tag in {3, 4}:
            pos += 4
        elif tag in {5, 6}:
            pos += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:
            pos += 2
        elif tag in {9, 10, 11, 12, 17, 18}:
            pos += 4
        elif tag == 15:
            pos += 3
        else:
            raise SolverError(f"{label}: unsupported Main-Class constant-pool tag {tag}")
        if pos > len(class_data):
            raise SolverError(f"{label}: Main-Class constant pool exceeds class file")
        index += 1

    if pos + 8 > len(class_data):
        raise SolverError(f"{label}: truncated Main-Class header")
    class_access = struct.unpack_from(">H", class_data, pos)[0]
    pos += 6  # access_flags, this_class, super_class
    interfaces = struct.unpack_from(">H", class_data, pos)[0]
    pos += 2 + interfaces * 2
    if pos + 2 > len(class_data):
        raise SolverError(f"{label}: truncated Main-Class interface table")

    def skip_members(position: int, collect_names: bool) -> tuple[int, list[str]]:
        if position + 2 > len(class_data):
            raise SolverError(f"{label}: truncated class member count")
        count = struct.unpack_from(">H", class_data, position)[0]
        position += 2
        names: list[str] = []
        for _ in range(count):
            if position + 8 > len(class_data):
                raise SolverError(f"{label}: truncated class member")
            _access, name_index, _descriptor = struct.unpack_from(">HHH", class_data, position)
            attr_count = struct.unpack_from(">H", class_data, position + 6)[0]
            position += 8
            if collect_names:
                if name_index >= len(cp) or cp[name_index] is None:
                    raise SolverError(f"{label}: method name does not reference UTF-8")
                names.append(cp[name_index] or "")
            for _ in range(attr_count):
                if position + 6 > len(class_data):
                    raise SolverError(f"{label}: truncated class member attribute")
                length = struct.unpack_from(">I", class_data, position + 2)[0]
                position += 6 + length
                if position > len(class_data):
                    raise SolverError(f"{label}: class member attribute exceeds class file")
        return position, names

    pos, _ = skip_members(pos, False)  # fields
    pos, method_names = skip_members(pos, True)
    return method_names, class_access, len(method_names), has_coroutines


def _elf_section_layout(
    data: bytes, label: str
) -> list[tuple[str, int, int, int, int]]:
    """Return ELF section name, type, virtual address, file offset, and flags."""
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in {1, 2} or data[5] not in {1, 2}:
        raise SolverError(f"{label}: invalid ELF header")
    elf_class, endian = data[4], "<" if data[5] == 1 else ">"
    if elf_class == 2:
        shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        minimum = 64
    else:
        shoff = struct.unpack_from(endian + "I", data, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 46)
        minimum = 40
    if (
        shentsize < minimum
        or shnum == 0
        or shstrndx >= shnum
        or shoff + shentsize * shnum > len(data)
    ):
        raise SolverError(f"{label}: invalid ELF section-header table")
    rows: list[tuple[int, int, int, int, int, int]] = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if elf_class == 2:
            name, kind = struct.unpack_from(endian + "II", data, base)
            flags, address, offset, size = struct.unpack_from(endian + "QQQQ", data, base + 8)
        else:
            name, kind = struct.unpack_from(endian + "II", data, base)
            flags, address, offset, size = struct.unpack_from(endian + "IIII", data, base + 8)
        if kind != 8 and offset + size > len(data):
            raise SolverError(f"{label}: ELF section {index} exceeds the file")
        rows.append((name, kind, flags, address, offset, size))
    string_row = rows[shstrndx]
    string_table = data[string_row[4] : string_row[4] + string_row[5]]
    result = []
    for name_offset, kind, flags, address, offset, size in rows:
        if name_offset >= len(string_table):
            raise SolverError(f"{label}: section-name offset is out of range")
        end = string_table.find(b"\0", name_offset)
        if end < 0:
            raise SolverError(f"{label}: unterminated ELF section name")
        try:
            name = string_table[name_offset:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: ELF section name is not UTF-8") from exc
        result.append((name, kind, flags, address, offset, size))
    return result


def _hcfg_storage(
    data: bytes, label: str, record_offset: int, *, from_base64: bool = False
) -> str:
    """Classify the winning HCFG by its observed carrier and exact code references."""
    if from_base64:
        return "base64"
    record = next(
        (
            (offset, key, config)
            for offset, key, config in _crc_valid_hcfg(data, label)
            if offset == record_offset
        ),
        None,
    )
    if record is None:
        raise SolverError(f"{label}: selected HCFG record is not present as literal bytes")
    if data.startswith(b"\x00asm"):
        for segment in _wasm_data_segments(data, label):
            if segment.find(b"HCFG") >= 0:
                return "wasm_data_segment"
        return "raw"
    if not data.startswith(b"\x7fELF"):
        return "raw"

    owner = next(
        (
            section
            for section in _elf_section_layout(data, label)
            if section[4] <= record_offset < section[4] + section[5]
        ),
        None,
    )
    if owner is None:
        return "raw"
    name, _kind, flags, address, file_offset, _size = owner
    if name == ".hcfg":
        return "raw_hcfg_section"
    if not (flags & 0x2):  # SHF_ALLOC: bytes are not mapped into memory.
        return "raw"
    target = address + record_offset - file_offset
    with tempfile.TemporaryDirectory(prefix="ctf-hcfg-storage-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(label).name
        path.write_bytes(data)
        disassembly = run_static_tool("objdump", "-drw", str(path))
    if re.search(rf"\b0x0*{target:x}\b", disassembly, re.IGNORECASE):
        return "raw_const_array"
    return "raw"


def _delivery_reference(question: dict[str, Any]) -> int | None:
    match = re.search(
        r"\bdelivery\s+(\d+)\b", artifact_hint(question), re.IGNORECASE
    )
    return max(0, int(match.group(1)) - 1) if match else None


def _validate_rust_answer(
    answer_id: str, value: str, question: dict[str, Any]
) -> None:
    answer_format = question.get("answer_format", {})
    kind = answer_format.get("kind")
    syntax = str(answer_format.get("syntax", ""))

    if kind == "json":
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise SolverError(f"{answer_id}: value is not valid JSON") from exc
        if not isinstance(decoded, list) or not all(
            isinstance(item, str) for item in decoded
        ):
            raise SolverError(f"{answer_id}: expected a JSON array of strings")
        return

    if kind == "pattern":
        if "exactly 64 lowercase hexadecimal characters" in syntax:
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise SolverError(f"{answer_id}: value does not match {syntax}")
            return
        padded_hex = re.search(
            r"exactly\s+(\d+)\s+lowercase hexadecimal digits",
            str(question.get("question", "")),
            re.IGNORECASE,
        )
        if "0x prefix" in syntax and padded_hex:
            width = int(padded_hex.group(1))
            if not re.fullmatch(rf"0x[0-9a-f]{{{width}}}", value):
                raise SolverError(f"{answer_id}: value does not match {syntax}")
            return

        # These labels are derived from parsed executable headers. Validate the
        # output against the field's semantic family; the shared validator does
        # not yet cover the wording used by these questions.
        _, field = parse_answer_id(answer_id)
        if field.endswith("_analysis_machine") or field.endswith(
            "_analysis_architecture"
        ):
            if not value or not re.fullmatch(r"[A-Za-z0-9 _().+-]+", value):
                raise SolverError(f"{answer_id}: invalid architecture label")
            return
        if field.endswith("_analysis_elf_type"):
            if value not in {"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE"}:
                raise SolverError(f"{answer_id}: unrecognized ELF e_type")
            return
        if field.endswith("_analysis_endianness"):
            if value not in {"little", "big"}:
                raise SolverError(f"{answer_id}: unrecognized ELF byte order")
            return
        if field.endswith("_analysis_format"):
            valid_formats = {
                "ELF",
                "ELF32",
                "ELF64",
                "PE",
                "PE32",
                "PE32+",
                "PE32_CLI",
                "PE32+_CLI",
                "PE_CLI",
                "ELF_CLI",
                "ELF32_CLI",
                "ELF64_CLI",
                "JAR",
                "elf",
                "pe",
                "pe_cli",
                "jar",
                "wasm",
                "neko_bytecode",
            }
            if value not in valid_formats:
                raise SolverError(f"{answer_id}: unrecognized executable format")
            return
        if field.endswith("_analysis_recover_code"):
            if value != "none" and not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
                raise SolverError(
                    f"{answer_id}: expected an unsigned base-10 integer or literal none"
                )
            return

    validate_answer_format(answer_id, value, question)


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    loaded = load_artifacts(artifact_paths)
    _, members_by_artifact = _runtime_members(artifact_paths, loaded)
    if len(loaded) != len(members_by_artifact):
        raise SolverError("Downloaded ELF deliveries could not be matched to their bytes")

    delivery_refs = {
        answer_id: _delivery_reference(questions[answer_id])
        for answer_id in answer_ids
    }
    ordered_refs = sorted(
        {ref for ref in delivery_refs.values() if ref is not None}
    )
    if ordered_refs and len(ordered_refs) != len(loaded):
        raise SolverError("Cannot map all assigned deliveries to their question hints")

    parse_cache: dict[tuple[str, str, str, int], Any] = {}

    def cached_parser(function: Any):
        def parse(data: bytes, label: str) -> Any:
            key = (
                function.__module__,
                function.__name__,
                label,
                id(data),
            )
            if key not in parse_cache:
                parse_cache[key] = function(data, label)
            return copy.deepcopy(parse_cache[key])

        return parse

    elf_fields_cached = cached_parser(_elf_fields)
    elf_literal_fields_cached = cached_parser(_elf_literal_section_fields)
    readelf_machine_cached = cached_parser(_readelf_machine)
    pe_header_cached = cached_parser(_pe_header)
    cpp_fields_cached = cached_parser(analyze_cpp)
    cpp_predicates_cached = cached_parser(_pe_discovery_engine_predicates)
    hcfg_records_cached = cached_parser(_crc_valid_hcfg)
    base64_hcfg_cached = cached_parser(_base64_hcfg)
    metadata_version_cached = cached_parser(_metadata_version)
    jar_main_hcfg_cached = cached_parser(_jar_main_hcfg)
    digest_cache: dict[int, str] = {}

    def sha256_hex(data: bytes) -> str:
        identity = id(data)
        if identity not in digest_cache:
            digest_cache[identity] = hashlib.sha256(data).hexdigest()
        return digest_cache[identity]

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    cache: dict[tuple[int, str], tuple[str, bytes]] = {}
    cpp_cache: dict[tuple[int, str], dict[str, str]] = {}
    hcfg_cache: dict[tuple[int, str], tuple[int, int, dict[str, Any]]] = {}

    for answer_id in answer_ids:
        _, field = parse_answer_id(answer_id)
        match = re.match(r"^(d\d{2})_", field)
        if not match:
            raise SolverError(f"{answer_id}: answer ID has no supported day specimen scope")
        day = match.group(1)
        delivery_index = 0
        if len(loaded) > 1:
            reference = delivery_refs[answer_id]
            if reference is None:
                raise SolverError(
                    f"{answer_id}: multiple deliveries were assigned without a delivery hint"
                )
            delivery_index = ordered_refs.index(reference)

        if day == "d22":
            matching = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith("d22--")
            ]
            if not matching:
                raise SolverError(
                    f"{answer_id}: assigned delivery has no d22-- specimen members"
                )
            if field.startswith("d22_artifact_sha256_"):
                ordinal = int(field.rsplit("_", 1)[1]) - 1
                if ordinal < 0 or ordinal >= len(matching):
                    raise SolverError(
                        f"{answer_id}: digest member ordinal exceeds the ordered d22-- list"
                    )
                label, payload = matching[ordinal]
                value = sha256_hex(payload)
                evidence_text = (
                    f"SHA-256 of d22-- member {ordinal + 1} in ZIP central-directory "
                    f"order ({label})"
                )
            else:
                runtime_configs = [
                    item
                    for item in matching
                    if pathlib.PurePosixPath(item[0]).name.lower().endswith(
                        ".runtimeconfig.json"
                    )
                ]
                if len(runtime_configs) != 1:
                    raise SolverError(
                        f"{answer_id}: primary runtimeconfig member is missing or ambiguous"
                    )
                runtime_label, _runtime_bytes = runtime_configs[0]
                primary_stem = pathlib.PurePosixPath(runtime_label).name[
                    : -len(".runtimeconfig.json")
                ]
                primary_matches = [
                    item
                    for item in matching
                    if pathlib.PurePosixPath(item[0]).name.lower()
                    == f"{primary_stem}.dll".lower()
                ]
                if len(primary_matches) != 1:
                    raise SolverError(
                        f"{answer_id}: DLL paired with the primary runtimeconfig is "
                        "missing or ambiguous"
                    )
                label, payload = primary_matches[0]
                executable_format, machine = _format_machine(payload, label)
                mapping = {
                    "analysis_format": executable_format,
                    "analysis_machine": machine,
                }
                needs_cli_metadata = field.endswith(
                    ("analysis_metadata_version", "analysis_hcfg_version")
                ) or "analysis_config_" in field
                if needs_cli_metadata and executable_format != "pe_cli":
                    raise SolverError(
                        f"{answer_id}: CLR metadata/HCFG was requested, but the "
                        f"primary member is classified as {executable_format}"
                    )
                if executable_format == "pe_cli":
                    version, _cli_machine, _pe_kind = metadata_version_cached(
                        payload, label
                    )
                    records = hcfg_records_cached(payload, label)
                    if not records:
                        raise SolverError(
                            f"{label}: no CRC32-valid HCFG record was found"
                        )
                    offset, key, config = records[0]
                    mapping.update(
                        {
                            "analysis_metadata_version": version,
                            "analysis_config_campaign": str(config.get("campaign", "")),
                            "analysis_config_domain": str(config.get("domain", "")),
                            "analysis_config_mutex": str(config.get("mutex", "")),
                            "analysis_config_url": str(config.get("url", "")),
                            "analysis_config_crc32_hex": (
                                f"0x{struct.unpack_from('<I', payload, offset + 8)[0]:08x}"
                            ),
                            "analysis_hcfg_version": str(payload[offset + 4]),
                        }
                    )
                    evidence_text = (
                        f"{label}: PE/CLI metadata root and first CRC32-valid HCFG "
                        f"record at file offset {offset:#x}"
                    )
                else:
                    evidence_text = f"{label}: executable magic and parsed container type"
                value = mapping.get(field.removeprefix("d22_"))
                if value is None:
                    raise SolverError(
                        f"{answer_id}: requested field is unavailable from the selected "
                        "primary assembly"
                    )
            _validate_rust_answer(answer_id, value, questions[answer_id])
            answers[answer_id] = value
            reasoning[answer_id] = f"Read {field}; {evidence_text}."
            continue
        if day == "d23":
            members = [
                item for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith("d23--")
            ]
            if not members:
                raise SolverError(f"{answer_id}: assigned delivery has no d23-- members")
            if field.startswith("d23_artifact_sha256_"):
                ordinal = int(field.rsplit("_", 1)[1]) - 1
                if ordinal < 0 or ordinal >= len(members):
                    raise SolverError(
                        f"{answer_id}: digest member ordinal exceeds the ordered d23-- list"
                    )
                label, payload = members[ordinal]
                value = sha256_hex(payload)
                evidence_text = (
                    f"SHA-256 of d23-- member {ordinal + 1} in ZIP central-directory "
                    f"order ({label})"
                )
            else:
                primary = [
                    item for item in members
                    if pathlib.PurePosixPath(item[0]).name.lower().endswith(".dll")
                    and not pathlib.PurePosixPath(item[0]).name.lower().endswith(
                        ".runtimeconfig.json"
                    )
                ]
                if len(primary) != 1:
                    raise SolverError(
                        f"{answer_id}: d23-- primary managed assembly is missing or ambiguous"
                    )
                label, payload = primary[0]
                executable_format, machine = _format_machine(payload, label)
                mapping = {
                    "analysis_format": executable_format,
                    "analysis_machine": machine,
                }
                if executable_format == "pe_cli":
                    version, _machine, _kind = metadata_version_cached(payload, label)
                    records = hcfg_records_cached(payload, label)
                    offset, key, config = records[0]
                    mapping.update(
                        {
                            "analysis_metadata_version": version,
                            "analysis_config_campaign": str(config.get("campaign", "")),
                            "analysis_config_domain": str(config.get("domain", "")),
                            "analysis_config_mutex": str(config.get("mutex", "")),
                            "analysis_config_url": str(config.get("url", "")),
                            "analysis_config_crc32_hex": (
                                f"0x{struct.unpack_from('<I', payload, offset + 8)[0]:08x}"
                            ),
                            "analysis_hcfg_version": str(payload[offset + 4]),
                            "analysis_xor_key_hex": f"0x{key:02x}",
                        }
                    )
                    evidence_text = (
                        f"{label}: parsed PE/CLI metadata and first CRC32-valid HCFG "
                        f"record at file offset {offset:#x}"
                    )
                else:
                    evidence_text = f"{label}: parsed executable container and machine"
                value = mapping.get(field.removeprefix("d23_"))
                if value is None:
                    raise SolverError(
                        f"{answer_id}: requested value is unavailable from the selected d23-- member"
                    )
            _validate_rust_answer(answer_id, value, questions[answer_id])
            answers[answer_id] = value
            reasoning[answer_id] = f"Read {field}; {evidence_text}."
            continue
        if day == "d24":
            members = [
                item for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith("d24--")
            ]
            if not members:
                raise SolverError(f"{answer_id}: assigned delivery has no d24-- members")
            if field.startswith("d24_artifact_sha256_"):
                ordinal = int(field.rsplit("_", 1)[1]) - 1
                if ordinal < 0 or ordinal >= len(members):
                    raise SolverError(
                        f"{answer_id}: digest member ordinal exceeds the ordered d24-- list"
                    )
                label, payload = members[ordinal]
                value = sha256_hex(payload)
                evidence_text = (
                    f"SHA-256 of d24-- member {ordinal + 1} in ZIP central-directory "
                    f"order ({label})"
                )
            else:
                role_files: dict[str, tuple[str, bytes]] = {}
                for role, suffix in (
                    ("vulnerable", "vulnerable.jar"),
                    ("corrected", "corrected.jar"),
                ):
                    matches = [
                        item for item in members
                        if pathlib.PurePosixPath(item[0]).name.lower().endswith(suffix)
                    ]
                    if len(matches) != 1:
                        raise SolverError(
                            f"{answer_id}: d24-- {role} JAR is missing or ambiguous"
                        )
                    role_files[role] = matches[0]
                parsed_roles: dict[
                    str, tuple[str, bytes, int, int, dict[str, Any], bytes, str]
                ] = {}
                for role, (jar_label, jar_bytes) in role_files.items():
                    offset, key, config, raw_payload, cp_evidence = (
                        _jar_any_class_hcfg(jar_bytes, jar_label)
                    )
                    parsed_roles[role] = (
                        jar_label,
                        jar_bytes,
                        offset,
                        key,
                        config,
                        raw_payload,
                        cp_evidence,
                    )
                vulnerable = parsed_roles["vulnerable"]
                corrected = parsed_roles["corrected"]
                if vulnerable[5] != corrected[5]:
                    raise SolverError(
                        "d24-- vulnerable and corrected JAR HCFG JSON payloads differ"
                    )

                if field.endswith("_vulnerable_format"):
                    selected_role = "vulnerable"
                elif field.endswith("_corrected_format") or field.startswith(
                    "d24_analysis_corrected_config_"
                ):
                    selected_role = "corrected"
                elif field.startswith("d24_analysis_config_"):
                    selected_role = "vulnerable"
                else:
                    raise SolverError(f"{answer_id}: unsupported Day 24 field")
                (
                    jar_label,
                    jar_bytes,
                    offset,
                    key,
                    config,
                    _raw_payload,
                    cp_evidence,
                ) = parsed_roles[selected_role]
                if field.endswith("_format"):
                    value, _machine = _format_machine(jar_bytes, jar_label)
                else:
                    key_name = field.rsplit("_", 1)[-1]
                    value = str(config.get(key_name, ""))
                    if not value:
                        raise SolverError(
                            f"{answer_id}: requested HCFG config key is missing or empty"
                        )
                evidence_text = (
                    f"{jar_label}: Base64 HCFG found in {cp_evidence}, "
                    f"CRC32 validated at decoded offset {offset:#x}; both role "
                    "payloads matched byte-for-byte"
                )
            _validate_rust_answer(answer_id, value, questions[answer_id])
            answers[answer_id] = value
            reasoning[answer_id] = f"Read {field}; {evidence_text}."
            continue

        if day == "d21":
            matching = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith("d21--")
            ]
            if len(matching) != 2:
                raise SolverError(
                    f"{answer_id}: expected two ordered d21-- specimen members, found {len(matching)}"
                )
            if field.startswith("d21_artifact_sha256_"):
                ordinal = int(field.rsplit("_", 1)[1]) - 1
                if ordinal < 0 or ordinal >= len(matching):
                    raise SolverError(f"{answer_id}: digest member ordinal is out of range")
                label, payload = matching[ordinal]
                value = sha256_hex(payload)
                evidence_text = (
                    f"SHA-256 of d21-- member {ordinal + 1} in ZIP central-directory order ({label})"
                )
            elif field.endswith("_loader_machine"):
                selected = [
                    item for item in matching
                    if pathlib.PurePosixPath(item[0]).name.lower().endswith("loader.elf")
                ]
                if len(selected) != 1:
                    raise SolverError(f"{answer_id}: loader.elf member is missing or ambiguous")
                label, payload = selected[0]
                value = _elf_machine_decimal(payload, label)
                evidence_text = f"unsigned ELF e_machine value from the hinted loader {label}"
            elif field.endswith("_plugin_machine"):
                selected = [
                    item for item in matching
                    if pathlib.PurePosixPath(item[0]).name.lower().endswith("plugin.cmxs")
                ]
                if len(selected) != 1:
                    raise SolverError(f"{answer_id}: plugin.cmxs member is missing or ambiguous")
                label, payload = selected[0]
                value = _elf_machine_decimal(payload, label)
                evidence_text = f"unsigned ELF e_machine value from the hinted plugin {label}"
            elif "config_" in field:
                selected = [
                    item for item in matching
                    if pathlib.PurePosixPath(item[0]).name.lower().endswith("plugin.cmxs")
                ]
                if len(selected) != 1:
                    raise SolverError(f"{answer_id}: plugin.cmxs member is missing or ambiguous")
                label, payload = selected[0]
                records = hcfg_records_cached(payload, label)
                _offset, _key, config = records[0]
                property_name = field.rsplit("_", 1)[1]
                raw_value = config.get(property_name)
                if not isinstance(raw_value, str):
                    raise SolverError(
                        f"{answer_id}: first CRC32-valid HCFG record has no string {property_name!r}"
                    )
                value = raw_value
                evidence_text = (
                    f"first CRC32-valid HCFG JSON record in {label}, property {property_name}"
                )
            else:
                raise SolverError(f"{answer_id}: unsupported Day 21 shared-library field")
            _validate_rust_answer(answer_id, value, questions[answer_id])
            answers[answer_id] = value
            reasoning[answer_id] = f"Read {field} from {label}; {evidence_text}."
            continue

        if day in {"d16", "d17", "d18", "d19", "d20"}:
            matching = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith(day + "--")
            ]
            if not matching:
                raise SolverError(f"{answer_id}: assigned ZIP has no {day} specimen")

            if field.startswith(day + "_artifact_sha256_"):
                ordinal = int(field.rsplit("_", 1)[1]) - 1
                if ordinal < 0 or ordinal >= len(matching):
                    raise SolverError(f"{answer_id}: digest member ordinal is out of range")
                label, payload = matching[ordinal]
                value = sha256_hex(payload)
                evidence_text = (
                    f"SHA-256 of {day} specimen {ordinal + 1} in ZIP central-directory order"
                )
            else:
                if day == "d16":
                    suffix = "compact.wasm" if "compact_" in field else "direct.wasm"
                    selected = [
                        item for item in matching
                        if pathlib.PurePosixPath(item[0]).name.lower().endswith(suffix)
                    ]
                    if len(selected) != 1:
                        raise SolverError(
                            f"{answer_id}: {suffix} member is missing or ambiguous"
                        )
                    label, payload = selected[0]
                    fmt, machine = _format_machine(payload, label)
                    mapping = {
                        "analysis_compact_architecture": machine if suffix == "compact.wasm" else "",
                        "analysis_compact_format": fmt if suffix == "compact.wasm" else "",
                        "analysis_direct_architecture": machine if suffix == "direct.wasm" else "",
                        "analysis_direct_format": fmt if suffix == "direct.wasm" else "",
                    }
                    config = None
                    if "config_" in field:
                        segment_records = []
                        for segment in _wasm_data_segments(payload, label):
                            try:
                                segment_records.extend(
                                    (offset, key, item)
                                    for offset, key, item in _crc_valid_hcfg(segment, label)
                                )
                            except SolverError:
                                continue
                        if len(segment_records) != 1:
                            raise SolverError(
                                f"{label}: expected one CRC32-valid HCFG record in WebAssembly data segments, found {len(segment_records)}"
                            )
                        _offset, key, config = segment_records[0]
                        prop = field.rsplit("_", 1)[1]
                        value = config.get(prop)
                        if not isinstance(value, str):
                            raise SolverError(
                                f"{answer_id}: HCFG JSON has no string {prop!r}"
                            )
                    else:
                        key = 0
                        value = mapping.get(field.removeprefix(day + "_"), "")
                    evidence_text = (
                        f"{label}: parsed the WebAssembly header and data-section payloads"
                        + (f"; decoded HCFG with XOR key 0x{key:02x}" if config is not None else "")
                    )
                else:
                    label, payload = matching[0]
                    fmt, machine = _format_machine(payload, label)
                    overlay_offset = 0
                    overlay_size = 0
                    resource_size = 0
                    hcfg_data = payload
                    if day == "d19":
                        overlay_offset, overlay_size, hcfg_data, _ = _overlay_hcfg(
                            payload, label, b"PK19"
                        )
                    elif day == "d20":
                        overlay_offset, resource_size, hcfg_data, _ = _overlay_hcfg(
                            payload, label, b"RS20"
                        )
                    if (
                        "config_" in field
                        or field.endswith("_hcfg_offset")
                        or field.endswith("_hcfg_version")
                        or field.endswith("_xor_key_hex")
                        or field.endswith("_config_crc32_hex")
                    ):
                        records = hcfg_records_cached(hcfg_data, label)
                        hcfg_offset, key, config = records[0]
                    mapping = {
                        "analysis_architecture": machine,
                        "analysis_machine": machine,
                        "analysis_format": fmt,
                        "analysis_overlay_offset": str(overlay_offset),
                        "analysis_overlay_size": str(overlay_size),
                        "analysis_hcfg_resource_size": str(resource_size),
                    }
                    if field.endswith("_config_crc32_hex"):
                        value = f"0x{struct.unpack_from('<I', hcfg_data, hcfg_offset + 8)[0]:08x}"
                    elif "config_" in field:
                        prop = field.rsplit("_", 1)[1]
                        value = config.get(prop)
                        if not isinstance(value, str):
                            raise SolverError(
                                f"{answer_id}: HCFG JSON has no string {prop!r}"
                            )
                    elif field.endswith("_hcfg_offset"):
                        value = str(hcfg_offset)
                    elif field.endswith("_hcfg_version"):
                        value = str(hcfg_data[hcfg_offset + 4])
                    elif field.endswith("_xor_key_hex"):
                        value = f"0x{key:02x}"
                    else:
                        value = mapping.get(field.removeprefix(day + "_"), "")
                    evidence_text = (
                        f"{label}: parsed {fmt} header"
                        + (
                            f", HCFG at file offset {hcfg_offset:#x}, XOR key {key:#04x}"
                            if "config_" in field or field.endswith("_hcfg_version")
                            or field.endswith("_xor_key_hex") or field.endswith("_config_crc32_hex")
                            else ""
                        )
                    )
            _validate_rust_answer(answer_id, value, questions[answer_id])
            answers[answer_id] = value
            reasoning[answer_id] = f"Read {field} from {label}; {evidence_text}."
            continue

        if (delivery_index, day) not in cache:
            matching = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith(day + "--")
            ]
            if not matching:
                raise SolverError(
                    f"{answer_id}: assigned delivery has no {day} specimen members"
                )
            # All fields name the ordered specimen group; preserve ZIP central-directory order.
            cache[(delivery_index, day)] = matching[0]
        label, payload = cache[(delivery_index, day)]

        if day == "d01":
            fields, evidence = elf_fields_cached(payload, label)
            literal_sections, literal_symbols = elf_literal_fields_cached(
                payload, label
            )
            marker, recover_code = _elf_marker_and_recover_code(payload, label)
            if payload[4] == 1:
                elf_endian = "<" if payload[5] == 1 else ">"
                entry_point = struct.unpack_from(elf_endian + "I", payload, 24)[0]
            elif payload[4] == 2:
                elf_endian = "<" if payload[5] == 1 else ">"
                entry_point = struct.unpack_from(elf_endian + "Q", payload, 24)[0]
            else:
                raise SolverError(f"{label}: unsupported ELF class for entry point")
            fields["section_names"] = json.dumps(
                literal_sections, separators=(",", ":")
            )
            fields["symbols"] = json.dumps(literal_symbols, separators=(",", ":"))
            fields["entry_point"] = f"0x{entry_point:x}"
            fields["has_symtab"] = (
                "true" if ".symtab" in literal_sections else "false"
            )
            evidence["entry_point"] = "ELF e_entry field in the assigned file header"
            evidence["has_symtab"] = (
                "ELF section-header-table presence of SHT_SYMTAB"
            )
            mapping = {
                "artifact_sha256_1": fields["sha256"],
                "analysis_elf_class": fields["elf_class"],
                "analysis_machine": fields["machine"],
                "analysis_section_names": fields["section_names"],
                "analysis_symbols": fields["symbols"],
                "analysis_disassembly": fields["disassembly"],
                "analysis_elf_type": fields["elf_type"],
                "analysis_endianness": fields["endianness"],
                "analysis_entry_point": fields["entry_point"],
                "analysis_has_symtab": fields["has_symtab"],
                "analysis_marker": marker,
                "analysis_recover_code": recover_code,
            }
            evidence["marker"] = "raw .huntress section bytes, with trailing NUL bytes removed"
            evidence["recover_code"] = (
                "SHT_SYMTAB STT_FUNC recover_code symbol bytes decoded as "
                "mov eax, imm32; ret, or none when that symbol is absent"
            )
            evidence_key = field.removeprefix("d01_")
            if evidence_key == "artifact_sha256_1":
                evidence_key = "sha256"
            else:
                evidence_key = evidence_key.removeprefix("analysis_")
            evidence_text = evidence[evidence_key]
            if evidence_key == "section_names":
                evidence_text = "ELF section-name string table in section-header-table order"
            elif evidence_key == "symbols":
                evidence_text = "literal nonempty SHT_SYMTAB names from its linked ELF string table"
        elif day == "d02":
            if payload.startswith(b"\x7fELF"):
                if (delivery_index, day) not in cpp_cache:
                    cpp_cache[(delivery_index, day)] = cpp_fields_cached(payload, label)
                fields = cpp_cache[(delivery_index, day)]
                if not fields:
                    raise SolverError(f"{label}: Day 2 specimen is not a supported C++ ELF")
                _, symbol_names = elf_literal_fields_cached(payload, label)
                mapping = {
                    "artifact_sha256_1": fields["sha256"],
                    "analysis_format": fields["format"],
                    "analysis_config_campaign": fields["campaign"],
                    "analysis_config_domain": fields["domain"],
                    "analysis_config_mutex": fields["mutex"],
                    "analysis_config_url": fields["url"],
                    "analysis_config_crc32_hex": fields["config_crc32"],
                    "analysis_xor_key_hex": fields["xor_key"],
                    "analysis_has_cpp_typeinfo": fields["has_typeinfo"],
                    "analysis_has_cpp_vtable": fields["has_vtable"],
                    "analysis_mangled_score_symbol": next(
                        (name for name in symbol_names if re.search(r"DiscoveryEngine.*score", name)),
                        "",
                    ),
                    "analysis_typeinfo_symbol": next(
                        (name for name in symbol_names if re.search(r"ZTI.*DiscoveryEngine", name)),
                        "",
                    ),
                }
                evidence_text = (
                    "C++ ELF header, CRC-checked .hcfg section, and literal SHT_SYMTAB "
                    "names in section and entry order"
                )
            elif payload.startswith(b"MZ"):
                pe_format, _, pe_sections = pe_header_cached(payload, label)
                symbol_names = _pe_coff_symbol_names(payload, label)
                has_typeinfo, has_vtable = cpp_predicates_cached(
                    payload, label
                )
                hcfg_sections = [item for item in pe_sections if item[0] == ".hcfg"]
                if len(hcfg_sections) != 1:
                    raise SolverError(
                        f"{label}: expected one PE section named .hcfg, found {len(hcfg_sections)}"
                    )
                _, section_offset, section_size = hcfg_sections[0]
                key, config = _decode_hcfg_record(
                    payload[section_offset : section_offset + section_size],
                    label,
                    section_offset,
                )
                crc = struct.unpack_from("<I", payload, section_offset + 8)[0]
                mapping = {
                    "artifact_sha256_1": hashlib.sha256(payload).hexdigest(),
                    "analysis_format": pe_format,
                    "analysis_config_campaign": str(config.get("campaign", "")),
                    "analysis_config_domain": str(config.get("domain", "")),
                    "analysis_config_mutex": str(config.get("mutex", "")),
                    "analysis_config_url": str(config.get("url", "")),
                    "analysis_config_crc32_hex": f"0x{crc:08x}",
                    "analysis_xor_key_hex": f"0x{key:02x}",
                    "analysis_has_cpp_typeinfo": has_typeinfo,
                    "analysis_has_cpp_vtable": has_vtable,
                    "analysis_mangled_score_symbol": next(
                        (name for name in symbol_names if re.search(r"DiscoveryEngine.*score", name)),
                        "",
                    ),
                    "analysis_typeinfo_symbol": next(
                        (name for name in symbol_names if re.search(r"ZTI.*DiscoveryEngine", name)),
                        "",
                    ),
                }
                evidence_text = (
                    f"{label}: PE section table, CRC32-checked .hcfg section "
                    f"at file offset {section_offset:#x}, and primary COFF symbol names "
                    "in raw table order, including section-definition symbols"
                )
            else:
                raise SolverError(f"{label}: Day 2 specimen is neither ELF nor PE")
        elif day == "d03":
            d03_members = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith("d03--")
            ]
            if len(d03_members) < 2:
                raise SolverError("Day 3 needs the managed assembly and its support member")
            dll_matches = [
                item
                for item in d03_members
                if pathlib.PurePosixPath(item[0]).name.lower().endswith(".dll")
            ]
            if len(dll_matches) != 1:
                raise SolverError("Day 3 primary managed assembly is missing or ambiguous")
            dll_label, dll_bytes = dll_matches[0]
            # The prompt numbers every d03-- member in central-directory order.
            sha1 = hashlib.sha256(d03_members[0][1]).hexdigest()
            sha2 = hashlib.sha256(d03_members[1][1]).hexdigest()
            version, machine, pe_kind = metadata_version_cached(dll_bytes, dll_label)
            valid_hcfg = hcfg_records_cached(dll_bytes, dll_label)
            if len(valid_hcfg) != 1:
                raise SolverError(
                    f"{dll_label}: expected one valid final-byte HCFG record, found {len(valid_hcfg)}"
                )
            offset, key, config = valid_hcfg[0]
            mapping = {
                "artifact_sha256_1": sha1,
                "artifact_sha256_2": sha2,
                "analysis_format": f"{pe_kind}_CLI",
                "analysis_machine": machine,
                "analysis_metadata_version": version,
                "analysis_config_campaign": str(config.get("campaign", "")),
                "analysis_config_domain": str(config.get("domain", "")),
                "analysis_config_mutex": str(config.get("mutex", "")),
                "analysis_config_url": str(config.get("url", "")),
                "analysis_config_crc32_hex": f"0x{struct.unpack_from('<I', dll_bytes, offset + 8)[0]:08x}",
                "analysis_hcfg_version": str(dll_bytes[offset + 4]),
                "analysis_xor_key_hex": f"0x{key:02x}",
            }
            if field == "artifact_sha256_1":
                evidence_text = (
                    f"SHA-256 of d03 member 1 in central-directory order: "
                    f"{d03_members[0][0]}"
                )
            elif field == "artifact_sha256_2":
                evidence_text = (
                    f"SHA-256 of d03 member 2 in central-directory order: "
                    f"{d03_members[1][0]}"
                )
            else:
                evidence_text = (
                    f"{dll_label}: CLR metadata root and HCFG at file offset {offset:#x}, "
                    f"XOR key {key:#04x}, validated decoded JSON"
                )
        elif day in {"d06", "d07"}:
            d06_members = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith(day + "--")
            ]
            if not d06_members:
                raise SolverError(f"{day.upper()} has no {day}-- specimen members")
            jar_members = [
                item
                for item in d06_members
                if pathlib.PurePosixPath(item[0]).name.lower().endswith(".jar")
            ]
            if len(jar_members) != 1:
                raise SolverError(f"{day.upper()} primary JAR is missing or ambiguous")
            jar_label, jar_bytes = jar_members[0]
            offset, key, config, cp_evidence, hcfg_record = jar_main_hcfg_cached(
                jar_bytes, jar_label
            )
            mapping = {
                "artifact_sha256_1": sha256_hex(d06_members[0][1]),
                "analysis_format": "JAR",
                "analysis_config_campaign": str(config.get("campaign", "")),
                "analysis_config_domain": str(config.get("domain", "")),
                "analysis_config_mutex": str(config.get("mutex", "")),
                "analysis_config_url": str(config.get("url", "")),
                "analysis_config_crc32_hex": f"0x{struct.unpack_from('<I', hcfg_record, 8)[0]:08x}",
                "analysis_hcfg_version": str(hcfg_record[4]),
                "analysis_xor_key_hex": f"0x{key:02x}",
            }
            method_names, class_access, method_count, has_coroutines = (
                _jar_main_class_details(jar_bytes, jar_label)
            )
            if day == "d06":
                mapping["analysis_methods"] = json.dumps(
                    method_names, separators=(",", ":")
                )
                mapping["analysis_access_flags"] = str(class_access)
            else:
                mapping["analysis_has_coroutine_runtime"] = (
                    "true" if has_coroutines else "false"
                )
                mapping["analysis_method_count"] = str(method_count)
            if day in {"d06", "d07"}:
                try:
                    with zipfile.ZipFile(BytesIO(jar_bytes)) as archive:
                        methods: list[str] = []
                        for info in archive.infolist():
                            method = {
                                zipfile.ZIP_STORED: "Stored",
                                zipfile.ZIP_DEFLATED: "Deflate",
                            }.get(info.compress_type, str(info.compress_type))
                            if method not in methods:
                                methods.append(method)
                except zipfile.BadZipFile as exc:
                    raise SolverError(f"{jar_label}: invalid assigned JAR") from exc
                mapping["analysis_compression_methods"] = json.dumps(
                    methods, separators=(",", ":")
                )
            evidence_text = (
                f"{jar_label}: parsed JAR manifest Main-Class and {cp_evidence}; "
                f"first CRC32-valid HCFG at decoded constant offset {offset:#x}, "
                f"XOR key {key:#04x}"
            )
            if field.endswith("analysis_compression_methods"):
                evidence_text = (
                    f"{jar_label}: central-directory compression codes in entry order, "
                    "including directory entries"
                )
        elif day in {"d08", "d09", "d11"}:
            spec_members = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith(day + "--")
            ]
            if not spec_members:
                raise SolverError(f"{day.upper()} has no {day}-- specimen members")
            specimen_label, specimen = spec_members[0]
            if specimen.startswith(b"\x7fELF"):
                machine = readelf_machine_cached(specimen, specimen_label)
                executable_format = "ELF"
                if len(specimen) < 64 or specimen[4] not in {1, 2}:
                    raise SolverError(f"{specimen_label}: ELF header is truncated or malformed")
                elf_class_bits = "32" if specimen[4] == 1 else "64"
            elif specimen.startswith(b"MZ"):
                executable_format, machine, _ = pe_header_cached(specimen, specimen_label)
                elf_class_bits = ""
            else:
                raise SolverError(f"{specimen_label}: unsupported executable magic")

            if day == "d08":
                from_base64 = False
                try:
                    records = hcfg_records_cached(specimen, specimen_label)
                    offset, key, config = records[0]
                    crc_value = struct.unpack_from("<I", specimen, offset + 8)[0]
                    carrier_offset = offset
                    config_source = "literal HCFG bytes"
                except SolverError:
                    (
                        offset,
                        key,
                        config,
                        crc_value,
                        carrier_offset,
                    ) = base64_hcfg_cached(specimen, specimen_label)
                    from_base64 = True
                    config_source = "first Base64 run containing a CRC32-valid HCFG record"
            else:
                (
                    offset,
                    key,
                    config,
                    crc_value,
                    carrier_offset,
                ) = base64_hcfg_cached(specimen, specimen_label)
                from_base64 = True
                config_source = "first Base64 run beginning with a CRC32-valid HCFG record"

            mapping = {
                "artifact_sha256_1": sha256_hex(spec_members[0][1]),
                "analysis_architecture": machine,
                "analysis_format": executable_format,
                "analysis_machine": machine,
                "analysis_elf_class": elf_class_bits,
                "analysis_config_campaign": str(config.get("campaign", "")),
                "analysis_config_domain": str(config.get("domain", "")),
                "analysis_config_mutex": str(config.get("mutex", "")),
                "analysis_config_url": str(config.get("url", "")),
                "analysis_config_crc32_hex": f"0x{crc_value:08x}",
                "analysis_hcfg_offset": str(
                    carrier_offset if day in {"d09", "d11"} else offset
                ),
                "analysis_hcfg_storage": _hcfg_storage(
                    specimen,
                    specimen_label,
                    offset,
                    from_base64=from_base64,
                ),
            }
            if day in {"d09", "d11"}:
                # The Base64 scanner accepts HCFG records only at supported
                # version 1, and returns that validated record's header.
                mapping["analysis_hcfg_version"] = "1"
            evidence_text = (
                f"{specimen_label}: {executable_format} header and {config_source} "
                f"at member byte offset {carrier_offset:#x}, decoded HCFG offset "
                f"{offset:#x}, XOR key {key:#04x}"
            )
        elif day in {"d13", "d14"}:
            spec_members = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith(day + "--")
            ]
            if not spec_members:
                raise SolverError(f"{day.upper()} has no {day}-- specimen members")
            specimen_label, specimen = spec_members[0]
            if specimen.startswith(b"\x7fELF"):
                machine = readelf_machine_cached(specimen, specimen_label)
                executable_format = "elf"
                section_names, _ = (
                    elf_literal_fields_cached(specimen, specimen_label)
                    if day == "d14"
                    else ([], [])
                )
            elif specimen.startswith(b"MZ"):
                pe_kind, machine, pe_sections = pe_header_cached(
                    specimen, specimen_label
                )
                executable_format = "pe"
                try:
                    metadata_version_cached(specimen, specimen_label)
                except SolverError:
                    pass
                else:
                    executable_format = "pe_cli"
                section_names = (
                    [item[0] for item in pe_sections] if day == "d14" else []
                )
                if not machine:
                    raise SolverError(
                        f"{specimen_label}: PE machine field has no normalized architecture"
                    )
            else:
                raise SolverError(
                    f"{specimen_label}: requested architecture and machine fields "
                    "cannot be derived from this specimen format"
                )

            if day == "d13":
                (
                    offset,
                    key,
                    config,
                    crc_value,
                    carrier_offset,
                ) = base64_hcfg_cached(specimen, specimen_label)
                config_source = (
                    "the first Base64 run beginning with a CRC32-valid HCFG record"
                )
            else:
                records = hcfg_records_cached(specimen, specimen_label)
                if not records:
                    raise SolverError(
                        f"{specimen_label}: no CRC32-valid literal HCFG record was found"
                    )
                offset, key, config = records[0]
                crc_value = struct.unpack_from("<I", specimen, offset + 8)[0]
                carrier_offset = offset
                config_source = "the first CRC32-valid literal HCFG record"

            mapping = {
                "artifact_sha256_1": sha256_hex(specimen),
                "analysis_architecture": machine,
                "analysis_format": executable_format,
                "analysis_machine": machine,
                "analysis_config_campaign": str(config.get("campaign", "")),
                "analysis_config_domain": str(config.get("domain", "")),
                "analysis_config_mutex": str(config.get("mutex", "")),
                "analysis_config_url": str(config.get("url", "")),
                "analysis_config_crc32_hex": f"0x{crc_value:08x}",
            }
            if day == "d13":
                mapping["analysis_hcfg_offset"] = str(carrier_offset)
                mapping["analysis_hcfg_version"] = "1"
                mapping["analysis_hcfg_storage"] = _hcfg_storage(
                    specimen, specimen_label, offset, from_base64=True
                )
            else:
                if day == "d14":
                    mapping["analysis_hcfg_offset"] = str(offset)
                mapping["analysis_has_hcfg_section"] = (
                    "true" if ".hcfg" in section_names else "false"
                )
                if day == "d14":
                    mapping["analysis_hcfg_storage"] = _hcfg_storage(
                        specimen, specimen_label, offset
                    )
            evidence_text = (
                f"{specimen_label}: {executable_format} header and {config_source} "
                f"at member byte offset {carrier_offset:#x}, decoded HCFG offset "
                f"{offset:#x}, XOR key {key:#04x}"
            )
        elif day == "d15":
            d15_members = [
                item
                for item in members_by_artifact[delivery_index]
                if pathlib.PurePosixPath(item[0]).name.lower().startswith("d15--")
            ]
            if len(d15_members) < 2:
                raise SolverError("Day 15 needs both d15-- specimens")

            def d15_specimen(role: str) -> tuple[str, bytes]:
                suffix = f"{role}.elf"
                matches = [
                    item
                    for item in d15_members
                    if pathlib.PurePosixPath(item[0]).name.lower().endswith(suffix)
                ]
                if len(matches) != 1:
                    raise SolverError(
                        f"Day 15 {role} specimen is missing or ambiguous"
                    )
                return matches[0]

            mapping = {
                "artifact_sha256_1": sha256_hex(d15_members[0][1]),
                "artifact_sha256_2": sha256_hex(d15_members[1][1]),
            }
            value_key = field.removeprefix(day + "_")
            if value_key.startswith("artifact_sha256_"):
                member_number = int(value_key.rsplit("_", 1)[1])
                evidence_text = (
                    f"SHA-256 of d15 member {member_number} in central-directory "
                    f"order: {d15_members[member_number - 1][0]}"
                )
            else:
                role = "stripped" if "_stripped_" in field else "symbolized"
                specimen_label, specimen = d15_specimen(role)
                if specimen.startswith(b"\x7fELF"):
                    if (
                        len(specimen) < 20
                        or specimen[4] not in {1, 2}
                        or specimen[5] not in {1, 2}
                    ):
                        raise SolverError(f"{specimen_label}: malformed ELF header")
                    endian = "<" if specimen[5] == 1 else ">"
                    machine_code = struct.unpack_from(endian + "H", specimen, 18)[0]
                    machine = readelf_machine_cached(specimen, specimen_label)
                    if machine != "x86-64":
                        raise SolverError(
                            f"{specimen_label}: expected the answerable x86-64 architecture"
                        )
                    executable_format = "elf"
                elif specimen.startswith(b"MZ"):
                    pe_kind, machine, _ = pe_header_cached(specimen, specimen_label)
                    pe_offset = struct.unpack_from("<I", specimen, 0x3C)[0]
                    machine_code = struct.unpack_from("<H", specimen, pe_offset + 4)[0]
                    executable_format = "pe"
                    try:
                        metadata_version_cached(specimen, specimen_label)
                    except SolverError:
                        pass
                    else:
                        executable_format = "pe_cli"
                elif specimen.startswith(b"\x00asm"):
                    if len(specimen) < 8 or specimen[4:8] != b"\x01\x00\x00\x00":
                        raise SolverError(f"{specimen_label}: invalid WebAssembly version")
                    machine = "wasm32"
                    machine_code = None
                    executable_format = "wasm"
                elif specimen.startswith(b"PK\x03\x04"):
                    with zipfile.ZipFile(BytesIO(specimen)) as archive:
                        if not any(name.lower().endswith(".class") for name in archive.namelist()):
                            raise SolverError(f"{specimen_label}: ZIP is not a Java archive")
                    machine = ""
                    machine_code = None
                    executable_format = "jar"
                elif specimen.startswith(b"NEKO"):
                    machine = ""
                    machine_code = None
                    executable_format = "neko_bytecode"
                else:
                    raise SolverError(
                        f"{specimen_label}: unrecognized Day 15 executable format"
                    )

                mapping.update(
                    {
                        f"analysis_{role}_architecture": machine,
                        f"analysis_{role}_format": executable_format,
                    }
                )
                if machine_code is not None:
                    mapping[f"analysis_{role}_machine"] = str(machine_code)
                if role == "stripped":
                    records = hcfg_records_cached(specimen, specimen_label)
                    if not records:
                        raise SolverError(
                            f"{specimen_label}: no CRC32-valid literal HCFG record was found"
                        )
                    offset, key, config = records[0]
                    mapping["analysis_stripped_config_campaign"] = str(
                        config.get("campaign", "")
                    )
                    mapping["analysis_stripped_config_domain"] = str(
                        config.get("domain", "")
                    )
                    mapping["analysis_stripped_config_mutex"] = str(
                        config.get("mutex", "")
                    )
                    mapping["analysis_stripped_config_url"] = str(
                        config.get("url", "")
                    )
                    evidence_text = (
                        f"{specimen_label}: {executable_format} magic/header, "
                        f"machine code {machine_code!r}, and first CRC32-valid literal "
                        f"HCFG at file offset {offset:#x}, XOR key {key:#04x}"
                    )
                else:
                    evidence_text = (
                        f"{specimen_label}: {executable_format} magic/header "
                        f"and machine code {machine_code!r}"
                    )
            value = mapping.get(value_key)
            if value is None or value == "":
                raise SolverError(
                    f"{answer_id}: requested Day 15 machine/architecture is unavailable"
                )
            _validate_rust_answer(answer_id, value, questions[answer_id])
            answers[answer_id] = value
            reasoning[answer_id] = (
                f"Read {field} from Day 15 evidence; {evidence_text}."
            )
            continue
        else:
            if day in {"d04", "d05", "d10", "d12"}:
                if payload.startswith(b"\x7fELF"):
                    machine = readelf_machine_cached(payload, label)
                    executable_format = "ELF"
                    if day == "d10":
                        section_names, _ = elf_literal_fields_cached(payload, label)
                elif day in {"d04", "d10"} and payload.startswith(b"MZ"):
                    _, machine, pe_sections = pe_header_cached(payload, label)
                    executable_format = "PE"
                    if day == "d10":
                        section_names = [item[0] for item in pe_sections]
                else:
                    raise SolverError(
                        f"{label}: requested {day.upper()} specimen has an unsupported executable format"
                    )
                valid_hcfg = hcfg_records_cached(payload, label)
                if day == "d04" and len(valid_hcfg) != 1:
                    raise SolverError(
                        f"{label}: expected one CRC32-valid HCFG record, found {len(valid_hcfg)}"
                    )
                offset, key, config = valid_hcfg[0]
                mapping = {
                    "artifact_sha256_1": sha256_hex(payload),
                    "analysis_architecture": machine,
                    "analysis_machine": machine,
                    "analysis_format": (
                        executable_format.casefold()
                        if day == "d12"
                        else executable_format
                    ),
                    "analysis_config_campaign": str(config.get("campaign", "")),
                    "analysis_config_domain": str(config.get("domain", "")),
                    "analysis_config_mutex": str(config.get("mutex", "")),
                    "analysis_config_url": str(config.get("url", "")),
                    "analysis_config_crc32_hex": f"0x{struct.unpack_from('<I', payload, offset + 8)[0]:08x}",
                    "analysis_hcfg_version": str(payload[offset + 4]),
                    "analysis_xor_key_hex": f"0x{key:02x}",
                }
                if day == "d10":
                    mapping["analysis_has_hcfg_section"] = (
                        "true" if any("hcfg" in name for name in section_names) else "false"
                    )
                if day == "d04":
                    if payload.startswith(b"\x7fELF"):
                        section_names, _ = elf_literal_fields_cached(payload, label)
                    else:
                        section_names = _pe_section_names(payload, label)
                    mapping["analysis_has_go_runtime"] = (
                        "true" if b"runtime.main" in payload else "false"
                    )
                    mapping["analysis_section_names"] = json.dumps(
                        section_names, separators=(",", ":")
                    )
                if day == "d05":
                    section_names, symbol_names = elf_literal_fields_cached(
                        payload, label
                    )
                    mapping["analysis_section_names"] = json.dumps(
                        section_names, separators=(",", ":")
                    )
                    mapping["analysis_has_rust_mangled_symbol"] = (
                        "true"
                        if any(name.startswith(("_ZN", "_R")) for name in symbol_names)
                        else "false"
                    )
                if day in {"d10", "d12"}:
                    mapping["analysis_hcfg_offset"] = str(offset)
                if day == "d12":
                    mapping["analysis_hcfg_storage"] = _hcfg_storage(
                        payload, label, offset
                    )
                header_kind = "ELF" if executable_format == "ELF" else "PE/COFF"
                hcfg_selection = (
                    "unique" if day == "d04" else "first"
                )
                evidence_text = (
                    f"{label}: {header_kind} header and {hcfg_selection} CRC32-valid "
                    f"HCFG at file offset {offset:#x}, XOR key {key:#04x}"
                )
            else:
                raise SolverError(f"{answer_id}: unsupported specimen field")

        value = mapping.get(field.removeprefix(day + "_"))
        if value is None or value == "":
            raise SolverError(f"{answer_id}: exact requested field is absent from evidence")
        _validate_rust_answer(answer_id, value, questions[answer_id])
        answers[answer_id] = value
        reasoning[answer_id] = f"Read {field} from {label}; {evidence_text}."

    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Analyze the assigned runtime-shape ELF and PE specimens")


if __name__ == "__main__":
    main()
