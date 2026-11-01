#!/usr/bin/env python3
"""Read a Windows Shell Link target from its LinkInfo structure."""

from __future__ import annotations

import pathlib
import struct
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    hinted_member,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


SHELL_LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _u32(data: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise SolverError(f"{label}: 32-bit field is outside the file")
    return struct.unpack_from("<I", data, offset)[0]


def _linkinfo_string(
    data: bytes,
    linkinfo_start: int,
    linkinfo_size: int,
    relative_offset: int,
    *,
    unicode: bool,
    label: str,
) -> str:
    if relative_offset == 0 or relative_offset >= linkinfo_size:
        raise SolverError(f"{label}: LinkInfo string offset is absent or out of range")
    start = linkinfo_start + relative_offset
    end_limit = linkinfo_start + linkinfo_size
    if unicode:
        if start + 2 > end_limit:
            raise SolverError(f"{label}: UTF-16 LinkInfo string starts outside the block")
        end = start
        while end + 1 < end_limit and data[end : end + 2] != b"\0\0":
            end += 2
        if end + 1 >= end_limit:
            raise SolverError(f"{label}: UTF-16 LinkInfo string is unterminated")
        encoding = "utf-16le"
    else:
        end = data.find(b"\0", start, end_limit)
        if end < 0:
            raise SolverError(f"{label}: LinkInfo string is unterminated")
        encoding = "cp1252"
    try:
        return data[start:end].decode(encoding)
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: LinkInfo string is invalid {encoding}") from exc


def _join_windows_path(base: str, suffix: str) -> str:
    if not suffix:
        return base
    if not base:
        return suffix
    return base.rstrip("\\/") + "\\" + suffix.lstrip("\\/")


def _network_name(data: bytes, offset: int, label: str) -> str:
    size = _u32(data, offset, label)
    if size < 0x14 or offset + size > len(data):
        raise SolverError(f"{label}: CommonNetworkRelativeLink size is invalid")
    net_name_offset = _u32(data, offset + 8, label)
    if net_name_offset == 0 or net_name_offset >= size:
        raise SolverError(f"{label}: network name offset is invalid")
    unicode_offset = 0
    if net_name_offset > 0x14 and size >= 0x1C:
        unicode_offset = _u32(data, offset + 20, label)
    if unicode_offset:
        start = offset + unicode_offset
        limit = offset + size
        if unicode_offset >= size or start + 2 > limit:
            raise SolverError(f"{label}: Unicode network name offset is invalid")
        end = start
        while end + 1 < limit and data[end : end + 2] != b"\0\0":
            end += 2
        if end + 1 >= limit:
            raise SolverError(f"{label}: Unicode network name is unterminated")
        try:
            return data[start:end].decode("utf-16le")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{label}: network name is invalid UTF-16LE") from exc
    start = offset + net_name_offset
    end = data.find(b"\0", start, offset + size)
    if end < 0:
        raise SolverError(f"{label}: network name is unterminated")
    try:
        return data[start:end].decode("cp1252")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: network name is invalid Windows text") from exc


def target_path(data: bytes, label: str) -> str:
    if len(data) < 0x4C or _u32(data, 0, label) != 0x4C:
        raise SolverError(f"{label}: ShellLinkHeader is missing or malformed")
    if data[4:20] != SHELL_LINK_CLSID:
        raise SolverError(f"{label}: ShellLink CLSID does not match the format")

    flags = _u32(data, 20, label)
    if not flags & 0x01:
        raise SolverError(f"{label}: IDList is absent; unsupported Shell Link layout")
    cursor = 0x4C
    if cursor + 2 > len(data):
        raise SolverError(f"{label}: LinkTargetIDListSize is truncated")
    id_list_size = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2 + id_list_size
    if cursor > len(data):
        raise SolverError(f"{label}: LinkTargetIDList exceeds the file")

    if not flags & 0x02:
        raise SolverError(f"{label}: LinkInfo is absent; target path is not established")
    linkinfo_start = cursor
    linkinfo_size = _u32(data, linkinfo_start, label)
    if linkinfo_size < 0x1C or linkinfo_start + linkinfo_size > len(data):
        raise SolverError(f"{label}: LinkInfo size is invalid")
    header_size = _u32(data, linkinfo_start + 4, label)
    linkinfo_flags = _u32(data, linkinfo_start + 8, label)
    if header_size < 0x1C or header_size > linkinfo_size:
        raise SolverError(f"{label}: LinkInfoHeader size is invalid")

    suffix_offset = _u32(data, linkinfo_start + 24, label)
    suffix = ""
    if suffix_offset:
        suffix_unicode_offset = (
            _u32(data, linkinfo_start + 32, label)
            if header_size >= 0x24
            else 0
        )
        suffix = _linkinfo_string(
            data,
            linkinfo_start,
            linkinfo_size,
            suffix_unicode_offset or suffix_offset,
            unicode=bool(suffix_unicode_offset),
            label=label,
        )

    if linkinfo_flags & 0x01:
        base_offset = _u32(data, linkinfo_start + 16, label)
        base_unicode_offset = (
            _u32(data, linkinfo_start + 28, label)
            if header_size >= 0x24
            else 0
        )
        base = _linkinfo_string(
            data,
            linkinfo_start,
            linkinfo_size,
            base_unicode_offset or base_offset,
            unicode=bool(base_unicode_offset),
            label=label,
        )
        return _join_windows_path(base, suffix)

    if linkinfo_flags & 0x02:
        network_offset = _u32(data, linkinfo_start + 20, label)
        if not network_offset or network_offset >= linkinfo_size:
            raise SolverError(f"{label}: CommonNetworkRelativeLink offset is invalid")
        base = _network_name(data, linkinfo_start + network_offset, label)
        return _join_windows_path(base, suffix)

    raise SolverError(f"{label}: LinkInfo has no local or network target path")


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
        hint = hinted_member(question)
        if not hint:
            raise SolverError(f"{answer_id}: no shortcut member is named in the artifact hint")
        label, data = unique_by_hint(
            members, hint, description=f"shortcut file for {answer_id}"
        )
        value = target_path(data, label)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"{label}: selected by the question's artifact hint; read the literal "
            "local or network target from the Shell Link LinkInfo structure"
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Read the target path from Windows Shell Link files")


if __name__ == "__main__":
    main()
