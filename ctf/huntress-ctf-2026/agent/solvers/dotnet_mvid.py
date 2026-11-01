#!/usr/bin/env python3
"""Read a managed PE module's MVID from its CLI metadata tables."""

from __future__ import annotations

import pathlib
import re
import struct
import uuid
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


def _metadata_streams(data: bytes, label: str) -> dict[str, bytes]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SolverError(f"{label}: MZ header is missing or truncated")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SolverError(f"{label}: PE signature or COFF header is missing")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 2:
        raise SolverError(f"{label}: PE optional header is truncated")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        directory_offset = optional + 96
    elif magic == 0x20B:
        directory_offset = optional + 112
    else:
        raise SolverError(f"{label}: unsupported PE optional-header magic {magic:#x}")
    number_offset = optional + (92 if magic == 0x10B else 108)
    if (
        number_offset + 4 > optional + optional_size
        or struct.unpack_from("<I", data, number_offset)[0] <= 14
        or directory_offset + 15 * 8 > optional + optional_size
    ):
        raise SolverError(f"{label}: PE has no CLI data-directory entry")
    cli_rva, cli_size = struct.unpack_from("<II", data, directory_offset + 14 * 8)
    if cli_rva == 0 or cli_size < 16:
        raise SolverError(f"{label}: PE has no CLI runtime header")

    sections: list[tuple[int, int, int, int]] = []
    section_table = optional + optional_size
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise SolverError(f"{label}: PE section table is truncated")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    def rva_to_offset(rva: int, size: int, description: str) -> int:
        for virtual_address, virtual_size, raw_offset, raw_size in sections:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva and rva + size <= virtual_address + span:
                file_offset = raw_offset + rva - virtual_address
                if file_offset + size <= raw_offset + raw_size and file_offset + size <= len(data):
                    return file_offset
        raise SolverError(f"{label}: {description} RVA {rva:#x} is not file-backed")

    cli_offset = rva_to_offset(cli_rva, 16, "CLI header")
    metadata_rva, metadata_size = struct.unpack_from("<II", data, cli_offset + 8)
    metadata_offset = rva_to_offset(metadata_rva, metadata_size, "metadata root")
    metadata_end = metadata_offset + metadata_size
    if data[metadata_offset : metadata_offset + 4] != b"BSJB" or metadata_size < 20:
        raise SolverError(f"{label}: CLR metadata root is missing its BSJB signature")

    version_length = struct.unpack_from("<I", data, metadata_offset + 12)[0]
    cursor = (metadata_offset + 16 + version_length + 3) & ~3
    if cursor + 4 > metadata_end:
        raise SolverError(f"{label}: CLR metadata stream header is truncated")
    _flags, stream_count = struct.unpack_from("<HH", data, cursor)
    cursor += 4
    streams: dict[str, bytes] = {}
    for _ in range(stream_count):
        if cursor + 8 > metadata_end:
            raise SolverError(f"{label}: CLR metadata stream descriptor is truncated")
        relative_offset, stream_size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        name_end = data.find(b"\0", cursor, min(cursor + 32, metadata_end))
        if name_end < 0:
            raise SolverError(f"{label}: CLR metadata stream name is unterminated")
        try:
            name = data[cursor:name_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: CLR metadata stream name is not ASCII") from exc
        cursor = (name_end + 4) & ~3
        if relative_offset + stream_size > metadata_size:
            raise SolverError(f"{label}: CLR metadata stream {name!r} exceeds its root")
        if name in streams:
            raise SolverError(f"{label}: duplicate CLR metadata stream {name!r}")
        start = metadata_offset + relative_offset
        streams[name] = data[start : start + stream_size]
    return streams


def mvid_guid(data: bytes, label: str) -> str:
    streams = _metadata_streams(data, label)
    tables_name = "#~" if "#~" in streams else "#-"
    if tables_name not in streams or "#GUID" not in streams:
        raise SolverError(f"{label}: CLR tables or #GUID metadata stream is missing")
    tables = streams[tables_name]
    if len(tables) < 24:
        raise SolverError(f"{label}: CLR tables stream is truncated")
    heap_sizes = tables[6]
    valid_mask = struct.unpack_from("<Q", tables, 8)[0]
    if not (valid_mask & 1):
        raise SolverError(f"{label}: CLR Module metadata table is absent")
    row_counts_offset = 24
    row_count = 0
    for table_id in range(64):
        if valid_mask & (1 << table_id):
            if row_counts_offset + 4 > len(tables):
                raise SolverError(f"{label}: CLR metadata row counts are truncated")
            count = struct.unpack_from("<I", tables, row_counts_offset)[0]
            row_counts_offset += 4
            if table_id == 0:
                row_count = count
    if row_count < 1:
        raise SolverError(f"{label}: CLR Module table has no rows")
    string_index_size = 4 if heap_sizes & 0x01 else 2
    guid_index_size = 4 if heap_sizes & 0x02 else 2
    mvid_index_offset = row_counts_offset + 2 + string_index_size
    if mvid_index_offset + guid_index_size > len(tables):
        raise SolverError(f"{label}: CLR Module row is truncated")
    if guid_index_size == 2:
        guid_index = struct.unpack_from("<H", tables, mvid_index_offset)[0]
    else:
        guid_index = struct.unpack_from("<I", tables, mvid_index_offset)[0]
    guid_heap = streams["#GUID"]
    if guid_index == 0:
        raise SolverError(f"{label}: CLR Module row has a nil MVID index")
    guid_start = (guid_index - 1) * 16
    if guid_start + 16 > len(guid_heap):
        raise SolverError(f"{label}: MVID index exceeds the #GUID heap")
    value = str(uuid.UUID(bytes_le=guid_heap[guid_start : guid_start + 16]))
    if not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", value):
        raise SolverError(f"{label}: decoded MVID is not canonical GUID text")
    return value


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    members = [
        member
        for path, payload in load_artifacts(artifact_paths)
        for member in iter_zip_files(payload, path.name)
    ]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = artifact_hint(question).strip()
        if not hint:
            raise SolverError(f"{answer_id}: no artifact hint selects a managed assembly")
        member_hint = hint.rsplit("->", 1)[-1].strip()
        label, content = unique_by_hint(
            members, member_hint, description=f"managed assembly for {answer_id}"
        )
        value = mvid_guid(content, label)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {label} from the question hint; read Module.Mvid from "
            "the CLR metadata tables and #GUID heap."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Read the MVID from a managed PE assembly")


if __name__ == "__main__":
    main()
