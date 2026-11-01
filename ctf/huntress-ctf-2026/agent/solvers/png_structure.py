#!/usr/bin/env python3
"""Read PNG IHDR dimensions from question-hinted ZIP members."""

from __future__ import annotations

import pathlib
import re
import struct
import zlib
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    hinted_member,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_ihdr_dimensions(data: bytes) -> tuple[int, int, list[str]]:
    if not data.startswith(PNG_SIGNATURE):
        raise SolverError("The hinted member does not have the PNG signature")

    offset = len(PNG_SIGNATURE)
    chunk_names: list[str] = []
    width = height = None
    saw_iend = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise SolverError("PNG chunk header or checksum is truncated")
        length = struct.unpack_from(">I", data, offset)[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 8 + length
        record_end = chunk_end + 4
        if record_end > len(data):
            raise SolverError("PNG chunk payload extends beyond the assigned file")
        try:
            name = chunk_type.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SolverError("PNG chunk type is not ASCII") from exc
        payload = data[offset + 8 : chunk_end]
        stored_crc = struct.unpack_from(">I", data, chunk_end)[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if actual_crc != stored_crc:
            raise SolverError(f"PNG {name} chunk has an invalid CRC")
        if not re.fullmatch(r"[A-Za-z]{4}", name):
            raise SolverError(f"PNG chunk type {name!r} is malformed")
        chunk_names.append(name)

        if not chunk_names[:-1]:
            if name != "IHDR":
                raise SolverError("PNG IHDR is not the first chunk")
        if name == "IHDR":
            if width is not None:
                raise SolverError("PNG contains multiple IHDR chunks")
            if length != 13:
                raise SolverError("PNG IHDR does not have its required 13-byte payload")
            width, height = struct.unpack_from(">II", payload)
            if width == 0 or height == 0:
                raise SolverError("PNG IHDR contains a zero dimension")
        elif name == "IEND":
            if length != 0:
                raise SolverError("PNG IEND chunk is not empty")
            saw_iend = True
            offset = record_end
            break
        offset = record_end

    if width is None or height is None:
        raise SolverError("PNG IHDR dimensions were not found")
    if not saw_iend:
        raise SolverError("PNG IEND chunk is missing")
    return width, height, chunk_names


def members_for_artifact(path: pathlib.Path, data: bytes) -> list[tuple[str, bytes]]:
    return list(iter_zip_files(data, path.name))


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    loaded = load_artifacts(artifact_paths)
    members_by_artifact = [
        members_for_artifact(path, data) for path, data in loaded
    ]
    all_members = [member for group in members_by_artifact for member in group]

    delivery_refs: dict[str, int | None] = {}
    for answer_id in answer_ids:
        match = re.search(
            r"\bdelivery\s+(\d+)\b",
            artifact_hint(questions[answer_id]),
            re.IGNORECASE,
        )
        delivery_refs[answer_id] = max(0, int(match.group(1)) - 1) if match else None
    ordered_refs = sorted({ref for ref in delivery_refs.values() if ref is not None})
    if ordered_refs and len(ordered_refs) != len(loaded):
        raise SolverError("Cannot map the assigned PNG deliveries to question hints")

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = hinted_member(question)
        if not hint:
            raise SolverError(f"{answer_id}: no PNG member hint was returned")
        if len(loaded) > 1:
            delivery_ref = delivery_refs[answer_id]
            if delivery_ref is None:
                raise SolverError(
                    f"{answer_id}: multiple artifact deliveries were assigned without "
                    "a delivery hint"
                )
            candidates = members_by_artifact[ordered_refs.index(delivery_ref)]
        else:
            candidates = all_members
        member_path, image = unique_by_hint(
            candidates, hint, description=f"PNG member for {answer_id}"
        )
        width, height, chunks = png_ihdr_dimensions(image)
        value = f"{width}x{height}"
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {member_path} using the question's member and delivery hints; "
            f"walked and CRC-checked its PNG chunks ({', '.join(chunks)}), then read "
            f"width={width} and height={height} from the 13-byte IHDR payload."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Read PNG dimensions from assigned IHDR chunk bytes")


if __name__ == "__main__":
    main()
