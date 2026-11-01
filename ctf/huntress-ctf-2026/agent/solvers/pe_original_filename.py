#!/usr/bin/env python3
"""Read OriginalFilename from the version resource of the hinted PE member."""

from __future__ import annotations

import pathlib
import struct
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


def _pe_sections(
    data: bytes, label: str
) -> tuple[int, int, list[tuple[int, int, int, int]]]:
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
    if number_offset + 4 > optional + optional_size:
        raise SolverError(f"{label}: PE data-directory count is truncated")
    directory_count = struct.unpack_from("<I", data, number_offset)[0]
    if directory_count <= 2 or directory_offset + 3 * 8 > optional + optional_size:
        raise SolverError(f"{label}: PE has no resource data directory")
    resource_rva, resource_size = struct.unpack_from(
        "<II", data, directory_offset + 2 * 8
    )
    if resource_rva == 0 or resource_size < 16:
        raise SolverError(f"{label}: PE resource directory is missing")

    section_table = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise SolverError(f"{label}: PE section table is truncated")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))
    return resource_rva, resource_size, sections


def _rva_to_offset(
    data: bytes,
    rva: int,
    size: int,
    sections: list[tuple[int, int, int, int]],
    label: str,
) -> int:
    for virtual_address, virtual_size, raw_offset, raw_size in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva and rva + size <= virtual_address + span:
            offset = raw_offset + rva - virtual_address
            if offset + size <= raw_offset + raw_size and offset + size <= len(data):
                return offset
    raise SolverError(f"{label}: resource RVA {rva:#x} is not file-backed")


def _version_resources(data: bytes, label: str) -> list[tuple[tuple[int | str, ...], bytes]]:
    resource_rva, resource_size, sections = _pe_sections(data, label)
    resource_offset = _rva_to_offset(
        data, resource_rva, resource_size, sections, label
    )
    resource_end = resource_offset + resource_size
    results: list[tuple[tuple[int | str, ...], bytes]] = []
    visited: set[int] = set()

    def check_range(relative: int, size: int, what: str) -> int:
        if relative < 0 or size < 0 or relative + size > resource_size:
            raise SolverError(f"{label}: resource {what} is outside the directory")
        return resource_offset + relative

    def decode_name(raw: int) -> int | str:
        if not raw & 0x80000000:
            return raw
        relative = raw & 0x7FFFFFFF
        position = check_range(relative, 2, "name length")
        char_count = struct.unpack_from("<H", data, position)[0]
        position = check_range(relative + 2, char_count * 2, "name")
        try:
            return data[position : position + char_count * 2].decode("utf-16le")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: resource name is not valid UTF-16LE") from exc

    def walk(relative: int, path: tuple[int | str, ...], depth: int) -> None:
        if depth > 8:
            raise SolverError(f"{label}: resource directory nesting is too deep")
        if relative in visited:
            raise SolverError(f"{label}: resource directory contains a cycle")
        visited.add(relative)
        position = check_range(relative, 16, "directory header")
        named, ids = struct.unpack_from("<HH", data, position + 12)
        count = named + ids
        entries_position = check_range(relative + 16, count * 8, "directory entries")
        for index in range(count):
            name_raw, target = struct.unpack_from(
                "<II", data, entries_position + index * 8
            )
            entry_name = decode_name(name_raw)
            child_path = path + (entry_name,)
            child_relative = target & 0x7FFFFFFF
            if target & 0x80000000:
                walk(child_relative, child_path, depth + 1)
            elif child_path and child_path[0] == 16:
                data_entry = check_range(child_relative, 16, "data entry")
                payload_rva, payload_size, _codepage, _reserved = struct.unpack_from(
                    "<IIII", data, data_entry
                )
                payload_offset = _rva_to_offset(
                    data, payload_rva, payload_size, sections, label
                )
                if payload_offset + payload_size > resource_end:
                    raise SolverError(
                        f"{label}: version resource payload exceeds the resource section"
                    )
                results.append(
                    (child_path, data[payload_offset : payload_offset + payload_size])
                )

    walk(0, (), 0)
    if not results:
        raise SolverError(f"{label}: no RT_VERSION (type 16) resource was found")
    return results


def _original_filename(version_data: bytes, label: str) -> str:
    matches: list[str] = []

    def walk_block(offset: int, parent_end: int, depth: int) -> int:
        if depth > 16 or offset + 6 > parent_end:
            raise SolverError(f"{label}: malformed VERSIONINFO block")
        length, value_length, value_type = struct.unpack_from(
            "<HHH", version_data, offset
        )
        end = offset + length
        if length < 6 or end > parent_end:
            raise SolverError(f"{label}: VERSIONINFO block length is invalid")
        key_start = offset + 6
        key_end = key_start
        while key_end + 1 < end and version_data[key_end : key_end + 2] != b"\0\0":
            key_end += 2
        if key_end + 1 >= end:
            raise SolverError(f"{label}: VERSIONINFO block key is unterminated")
        try:
            key = version_data[key_start:key_end].decode("utf-16le")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: VERSIONINFO key is invalid UTF-16LE") from exc
        value_start = (key_end + 2 + 3) & ~3
        value_bytes = value_length * 2 if value_type == 1 else value_length
        value_end = value_start + value_bytes
        if value_end > end:
            raise SolverError(f"{label}: VERSIONINFO value exceeds its block")
        if key == "OriginalFilename":
            if value_type != 1 or value_length == 0:
                raise SolverError(f"{label}: OriginalFilename is not a text value")
            try:
                value = version_data[value_start:value_end].decode("utf-16le")
            except UnicodeDecodeError as exc:
                raise SolverError(
                    f"{label}: OriginalFilename is invalid UTF-16LE"
                ) from exc
            value = value.rstrip("\0")
            if not value:
                raise SolverError(f"{label}: OriginalFilename is empty")
            matches.append(value)

        children_start = (value_end + 3) & ~3
        cursor = children_start
        while cursor + 6 <= end:
            child_length = struct.unpack_from("<H", version_data, cursor)[0]
            if child_length == 0:
                break
            next_cursor = walk_block(cursor, end, depth + 1)
            if next_cursor <= cursor:
                raise SolverError(f"{label}: VERSIONINFO child did not advance")
            cursor = (next_cursor + 3) & ~3
        return end

    walk_block(0, len(version_data), 0)
    unique = set(matches)
    if len(unique) != 1:
        raise SolverError(
            f"{label}: expected one consistent OriginalFilename value, found "
            f"{len(unique)} distinct values"
        )
    return next(iter(unique))


def original_filename(data: bytes, label: str) -> tuple[str, str]:
    resources = _version_resources(data, label)
    values = [_original_filename(payload, label) for _path, payload in resources]
    unique = set(values)
    if len(unique) != 1:
        raise SolverError(
            f"{label}: version resources disagree on OriginalFilename"
        )
    paths = ", ".join(" / ".join(map(str, path)) for path, _ in resources)
    return next(iter(unique)), f"RT_VERSION resource path(s) {paths}"


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    artifacts = load_artifacts(artifact_paths)
    candidates = [
        member
        for path, payload in artifacts
        for member in iter_zip_files(payload, path.name)
    ]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = artifact_hint(question).strip()
        member_hint = hint.rsplit("->", 1)[-1].strip() if "->" in hint else hint
        if not member_hint:
            raise SolverError(f"{answer_id}: question has no artifact member hint")
        label, content = unique_by_hint(
            candidates, member_hint, description=f"PE member for {answer_id}"
        )
        value, resource_evidence = original_filename(content, label)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {label} from this question's artifact hint; decoded the "
            f"PE RT_VERSION resource statically ({resource_evidence}) and read "
            "the literal OriginalFilename string."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Read PE OriginalFilename version-resource strings")


if __name__ == "__main__":
    main()
