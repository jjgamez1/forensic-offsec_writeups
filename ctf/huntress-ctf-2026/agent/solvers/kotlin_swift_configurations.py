#!/usr/bin/env python3
"""Statically inspect the Kotlin and Swift staged configuration bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import struct
import zipfile
from io import BytesIO
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    questions_by_id,
    run_cli,
)
from agent.solvers.managed_configuration import _elf_fields, _metadata_version
from agent.solvers.mangled import analyze_cpp, analyze_pe
from agent.solvers.rust_runtime_shapes import (
    _crc_valid_hcfg,
    _decode_hcfg_record,
    _elf_literal_section_fields,
    _pe_header,
    _readelf_machine,
    _runtime_members,
    _validate_rust_answer,
)


def _class_utf8_constants(data: bytes, label: str) -> list[str]:
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
        if tag == 1:
            if position + 2 > len(data):
                raise SolverError(f"{label}: truncated Java UTF-8 constant")
            length = struct.unpack_from(">H", data, position)[0]
            position += 2
            end = position + length
            if end > len(data):
                raise SolverError(f"{label}: Java UTF-8 constant exceeds the class file")
            encoded = data[position:end]
            units = bytearray()
            cursor = 0
            while cursor < len(encoded):
                first = encoded[cursor]
                if first <= 0x7F:
                    unit = first
                    cursor += 1
                elif 0xC0 <= first <= 0xDF and cursor + 1 < len(encoded):
                    second = encoded[cursor + 1]
                    if second & 0xC0 != 0x80:
                        raise SolverError(f"{label}: malformed Java modified UTF-8")
                    unit = ((first & 0x1F) << 6) | (second & 0x3F)
                    cursor += 2
                elif 0xE0 <= first <= 0xEF and cursor + 2 < len(encoded):
                    second, third = encoded[cursor + 1 : cursor + 3]
                    if second & 0xC0 != 0x80 or third & 0xC0 != 0x80:
                        raise SolverError(f"{label}: malformed Java modified UTF-8")
                    unit = (
                        ((first & 0x0F) << 12)
                        | ((second & 0x3F) << 6)
                        | (third & 0x3F)
                    )
                    cursor += 3
                else:
                    raise SolverError(f"{label}: malformed Java modified UTF-8")
                units.extend(struct.pack(">H", unit))
            try:
                constants.append(bytes(units).decode("utf-16-be", errors="surrogatepass"))
            except UnicodeDecodeError as exc:
                raise SolverError(f"{label}: malformed Java modified UTF-8") from exc
            position = end
        elif tag in {3, 4}:
            position += 4
        elif tag in {5, 6}:
            position += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:
            position += 2
        elif tag in {9, 10, 11, 12, 17, 18}:
            position += 4
        elif tag == 15:
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
            main_match = re.search(r"(?im)^Main-Class:\s*([^\r\n]+)", unfolded)
            if main_match is None:
                raise SolverError(f"{label}: JAR manifest has no Main-Class")
            class_name = main_match.group(1).strip().replace(".", "/") + ".class"
            class_matches = [
                info for info in archive.infolist() if info.filename == class_name
            ]
            if len(class_matches) != 1:
                raise SolverError(f"{label}: Main-Class entry is missing or ambiguous")
            class_data = archive.read(class_matches[0])
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError) as exc:
        raise SolverError(f"{label}: assigned JAR could not be read statically") from exc
    for constant_index, value in enumerate(_class_utf8_constants(class_data, label), 1):
        if len(value) < 80 or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            continue
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error):
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
    raise SolverError(f"{label}: no Base64 class constant contains a valid HCFG record")


def _delivery_index(question: dict[str, Any], count: int) -> int:
    match = re.search(r"\bdelivery\s+(\d+)\b", artifact_hint(question), re.I)
    if match is None:
        if count == 1:
            return 0
        raise SolverError("Multiple assigned deliveries require an explicit delivery hint")
    index = int(match.group(1)) - 1
    if not 0 <= index < count:
        raise SolverError(f"Invalid assigned delivery number {index + 1}")
    return index


def _members_for_day(
    delivery: list[tuple[str, bytes]], day: str, answer_id: str
) -> list[tuple[str, bytes]]:
    matches = [
        item
        for item in delivery
        if pathlib.PurePosixPath(item[0]).name.lower().startswith(day + "--")
    ]
    if not matches:
        raise SolverError(f"{answer_id}: assigned delivery has no {day} specimen members")
    return matches


def _d08_config(data: bytes, label: str) -> tuple[int, int, dict[str, Any]]:
    try:
        literal = _crc_valid_hcfg(data, label)
    except SolverError:
        literal = []
    if literal:
        offset, key, config = literal[0]
        return offset, key, config

    for match in re.finditer(rb"[A-Za-z0-9+/]{100,}={0,2}", data):
        try:
            decoded = base64.b64decode(match.group(0), validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        try:
            records = _crc_valid_hcfg(decoded, label)
        except SolverError:
            continue
        if records:
            offset, key, config = records[0]
            return offset, key, config
    raise SolverError(f"{label}: no CRC32-valid literal or Base64 HCFG JSON record")


def _build_day_fields(
    answer_id: str, day: str, label: str, payload: bytes,
    specimens: list[tuple[str, bytes]],
) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    evidence = label
    if day == "d01":
        elf_fields, _ = _elf_fields(payload, label)
        section_names, symbols = _elf_literal_section_fields(payload, label)
        elf_fields["section_names"] = json.dumps(section_names, separators=(",", ":"))
        elf_fields["symbols"] = json.dumps(symbols, separators=(",", ":"))
        entry_offset = 24 if payload[4] == 2 else 24
        entry_format = "<Q" if payload[5] == 1 and payload[4] == 2 else (
            ">Q" if payload[4] == 2 else ("<I" if payload[5] == 1 else ">I")
        )
        entry_point = struct.unpack_from(entry_format, payload, entry_offset)[0]
        fields = {
            "artifact_sha256_1": elf_fields["sha256"],
            "analysis_elf_class": elf_fields["elf_class"],
            "analysis_machine": elf_fields["machine"],
            "analysis_section_names": elf_fields["section_names"],
            "analysis_symbols": elf_fields["symbols"],
            "analysis_disassembly": elf_fields["disassembly"],
            "analysis_elf_type": elf_fields["elf_type"],
            "analysis_endianness": elf_fields["endianness"],
            "analysis_entry_point": f"0x{entry_point:x}",
            "analysis_has_symtab": "true" if ".symtab" in section_names else "false",
        }
        evidence = f"{label}: ELF header and literal section/symbol tables"

    elif day == "d02":
        if payload.startswith(b"MZ"):
            cpp = analyze_pe(payload, label)
        else:
            cpp = analyze_cpp(payload, label)
        if not cpp:
            raise SolverError(f"{label}: expected a native C++ HCFG specimen")
        fields = {
            "artifact_sha256_1": cpp["sha256"],
            "analysis_format": cpp["format"],
            "analysis_config_campaign": cpp["campaign"],
            "analysis_config_domain": cpp["domain"],
            "analysis_config_mutex": cpp["mutex"],
            "analysis_config_url": cpp["url"],
            "analysis_config_crc32_hex": cpp["config_crc32"],
            "analysis_xor_key_hex": cpp["xor_key"],
            "analysis_has_cpp_typeinfo": cpp["has_typeinfo"],
            "analysis_has_cpp_vtable": cpp["has_vtable"],
        }
        evidence = f"{label}: ELF .hcfg and C++ symbol table"

    elif day == "d03":
        dlls = [
            item
            for item in specimens
            if pathlib.PurePosixPath(item[0]).name.lower().endswith(".dll")
        ]
        if len(dlls) != 1:
            raise SolverError(f"{answer_id}: expected one d03 managed DLL")
        dll_label, dll_data = dlls[0]
        version, machine, pe_kind = _metadata_version(dll_data, dll_label)
        records = _crc_valid_hcfg(dll_data, dll_label)
        if len(records) != 1:
            raise SolverError(f"{dll_label}: expected one CRC32-valid HCFG record")
        offset, key, config = records[0]
        record_length = struct.unpack_from("<H", dll_data, offset + 6)[0]
        record = dll_data[offset : offset + 12 + record_length]
        crc = struct.unpack_from("<I", record, 8)[0]
        fields = {
            "artifact_sha256_1": hashlib.sha256(specimens[0][1]).hexdigest(),
            "artifact_sha256_2": hashlib.sha256(specimens[1][1]).hexdigest()
            if len(specimens) > 1
            else "",
            "analysis_format": f"{pe_kind}_CLI",
            "analysis_machine": machine,
            "analysis_metadata_version": version,
            "analysis_config_campaign": str(config.get("campaign", "")),
            "analysis_config_domain": str(config.get("domain", "")),
            "analysis_config_mutex": str(config.get("mutex", "")),
            "analysis_config_url": str(config.get("url", "")),
            "analysis_config_crc32_hex": f"0x{crc:08x}",
        }
        evidence = f"{dll_label}: CLR metadata and CRC32-validated HCFG at {offset:#x}, key {key:#04x}"

    elif day in {"d04", "d05"}:
        if payload.startswith(b"\x7fELF"):
            machine = _readelf_machine(payload, label)
            executable_format = "ELF"
        elif payload.startswith(b"MZ") and day == "d04":
            _, machine, _ = _pe_header(payload, label)
            executable_format = "PE"
        else:
            raise SolverError(f"{label}: unsupported {day.upper()} executable bytes")
        records = _crc_valid_hcfg(payload, label)
        if day == "d04" and len(records) != 1:
            raise SolverError(f"{label}: expected one valid Go HCFG record")
        offset, key, config = records[0]
        crc = struct.unpack_from("<I", payload, offset + 8)[0]
        fields = {
            "artifact_sha256_1": hashlib.sha256(payload).hexdigest(),
            "analysis_architecture": machine,
            "analysis_format": executable_format,
            "analysis_config_campaign": str(config.get("campaign", "")),
            "analysis_config_domain": str(config.get("domain", "")),
            "analysis_config_mutex": str(config.get("mutex", "")),
            "analysis_config_url": str(config.get("url", "")),
            "analysis_config_crc32_hex": f"0x{crc:08x}",
            "analysis_hcfg_version": str(payload[offset + 4]),
            "analysis_xor_key_hex": f"0x{key:02x}",
        }
        evidence = f"{label}: executable header and HCFG at {offset:#x}, key {key:#04x}"

    elif day in {"d06", "d07"}:
        jars = [
            item
            for item in specimens
            if pathlib.PurePosixPath(item[0]).name.lower().endswith(".jar")
        ]
        if len(jars) != 1:
            raise SolverError(f"{answer_id}: expected one {day.upper()} JAR")
        jar_label, jar_data = jars[0]
        offset, key, config, cp_evidence, record = _jar_main_hcfg(jar_data, jar_label)
        crc = struct.unpack_from("<I", record, 8)[0]
        with zipfile.ZipFile(BytesIO(jar_data)) as jar:
            methods = {info.compress_type for info in jar.infolist()}
        compression_methods = sorted(
            {0: "Stored", 8: "Deflate"}.get(method, str(method))
            for method in methods
        )
        fields = {
            "artifact_sha256_1": hashlib.sha256(specimens[0][1]).hexdigest(),
            "analysis_format": "JAR",
            "analysis_config_campaign": str(config.get("campaign", "")),
            "analysis_config_domain": str(config.get("domain", "")),
            "analysis_config_mutex": str(config.get("mutex", "")),
            "analysis_config_url": str(config.get("url", "")),
            "analysis_config_crc32_hex": f"0x{crc:08x}",
            "analysis_hcfg_version": str(record[4]),
            "analysis_xor_key_hex": f"0x{key:02x}",
            "analysis_compression_methods": json.dumps(
                compression_methods, separators=(",", ":")
            ),
        }
        evidence = f"{jar_label}: Main-Class {cp_evidence}, HCFG at constant offset {offset:#x}"

    elif day == "d08":
        if not payload.startswith(b"\x7fELF"):
            raise SolverError(f"{label}: d08 specimen is not ELF")
        elf_class_byte = payload[4]
        if elf_class_byte not in {1, 2}:
            raise SolverError(f"{label}: unsupported ELF EI_CLASS")
        machine = _readelf_machine(payload, label)
        offset, key, config = _d08_config(payload, label)
        crc = struct.unpack_from("<I", payload, offset + 8)[0] if payload[offset : offset + 4] == b"HCFG" else None
        if crc is None:
            # The HCFG record was found in a Base64-decoded run.
            for match in re.finditer(rb"[A-Za-z0-9+/]{100,}={0,2}", payload):
                try:
                    decoded = base64.b64decode(match.group(0), validate=True)
                except (ValueError, base64.binascii.Error):
                    continue
                try:
                    valid = _crc_valid_hcfg(decoded, label)
                except SolverError:
                    continue
                if valid and valid[0][1] == key and valid[0][2] == config:
                    crc = struct.unpack_from("<I", decoded, valid[0][0] + 8)[0]
                    break
        if crc is None:
            raise SolverError(f"{label}: HCFG CRC32 evidence could not be located")
        elf_class = "32" if elf_class_byte == 1 else "64"
        fields = {
            "artifact_sha256_1": hashlib.sha256(payload).hexdigest(),
            "analysis_architecture": machine,
            "analysis_elf_class": elf_class,
            "analysis_format": "ELF",
            "analysis_machine": machine,
            "analysis_config_campaign": str(config.get("campaign", "")),
            "analysis_config_domain": str(config.get("domain", "")),
            "analysis_config_mutex": str(config.get("mutex", "")),
            "analysis_config_url": str(config.get("url", "")),
            "analysis_config_crc32_hex": f"0x{crc:08x}",
        }
        evidence = f"{label}: ELF header and first CRC32-valid literal/Base64 HCFG at {offset:#x}"

    else:
        raise SolverError(f"{answer_id}: unsupported day")

    return fields, evidence


def _solve_one(
    answer_id: str,
    question: dict[str, Any],
    delivery: list[tuple[str, bytes]],
    field_cache: dict[tuple[int, str, str], tuple[dict[str, str], str]] | None = None,
) -> tuple[str, str]:
    _, field = parse_answer_id(answer_id)
    day_match = re.match(r"^(d0[1-8])_", field)
    if day_match is None:
        raise SolverError(f"{answer_id}: answer field has no d01–d08 scope")
    day = day_match.group(1)
    specimens = _members_for_day(delivery, day, answer_id)
    label, payload = specimens[0]
    suffix = field.removeprefix(day + "_")
    cache_key = (id(delivery), day, label)
    cached = field_cache.get(cache_key) if field_cache is not None else None
    if cached is None:
        fields, evidence = _build_day_fields(answer_id, day, label, payload, specimens)
        if field_cache is not None:
            field_cache[cache_key] = (fields, evidence)
    else:
        fields, evidence = cached

    if suffix not in fields or not fields[suffix]:
        raise SolverError(f"{answer_id}: no exact evidence for requested field {suffix!r}")
    value = fields[suffix]
    _validate_rust_answer(answer_id, value, question)
    return value, evidence


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    _, deliveries = _runtime_members(artifact_paths)
    if len(deliveries) != len(artifact_paths):
        raise SolverError("Could not preserve each delivery's member list")
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    field_cache: dict[tuple[int, str, str], tuple[dict[str, str], str]] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        delivery_index = _delivery_index(question, len(deliveries))
        value, evidence = _solve_one(
            answer_id, question, deliveries[delivery_index], field_cache
        )
        answers[answer_id] = value
        reasoning[answer_id] = f"Read the requested field from assigned bytes; {evidence}."
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Analyze Kotlin and Swift staged configuration specimens")


if __name__ == "__main__":
    main()
