#!/usr/bin/env python3
"""Read JPEG dimensions from the Start Of Frame structure."""

from __future__ import annotations

import pathlib
import re
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


SOF_MARKERS = {
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
}


def jpeg_sof_dimensions(data: bytes) -> tuple[int, int]:
    if not data.startswith(b"\xff\xd8"):
        raise SolverError("The hinted member does not have JPEG SOI bytes")
    offset = 2
    while offset < len(data):
        if data[offset] != 0xFF:
            raise SolverError("Malformed JPEG marker stream before an SOF segment")
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if offset + 2 > len(data):
            break
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(data):
            raise SolverError("JPEG segment length is invalid")
        if marker in SOF_MARKERS:
            if segment_length < 8:
                raise SolverError("JPEG SOF segment is too short for dimensions")
            height = int.from_bytes(data[offset + 3 : offset + 5], "big")
            width = int.from_bytes(data[offset + 5 : offset + 7], "big")
            if width <= 0 or height <= 0:
                raise SolverError("JPEG SOF contains a zero dimension")
            return width, height
        if marker == 0xDA:  # SOS: frame headers must precede image data.
            break
        offset += segment_length
    raise SolverError("No JPEG Start Of Frame dimensions were found")


def archive_members(paths: list[pathlib.Path]) -> list[tuple[str, bytes]]:
    members = []
    for path, data in load_artifacts(paths):
        members.extend(iter_zip_files(data, path.name))
    return members


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    members_by_artifact = [archive_members([path]) for path in artifact_paths]
    all_members = [member for delivery in members_by_artifact for member in delivery]
    delivery_refs = {}
    for answer_id in answer_ids:
        match = re.search(
            r"\bdelivery\s+(\d+)\b",
            artifact_hint(questions[answer_id]),
            re.IGNORECASE,
        )
        delivery_refs[answer_id] = max(0, int(match.group(1)) - 1) if match else None
    ordered_refs = sorted({ref for ref in delivery_refs.values() if ref is not None})
    if ordered_refs and len(ordered_refs) != len(artifact_paths):
        raise SolverError("Cannot map the assigned JPEG deliveries to question hints")
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = hinted_member(question)
        if hint is None:
            raise SolverError(f"{answer_id}: no exact JPEG member hint was returned")
        if len(artifact_paths) > 1:
            delivery_ref = delivery_refs[answer_id]
            if delivery_ref is None:
                raise SolverError(
                    f"{answer_id}: multiple artifacts were assigned but the question "
                    "does not identify its delivery"
                )
            members = members_by_artifact[ordered_refs.index(delivery_ref)]
        else:
            members = all_members
        member_path, image = unique_by_hint(
            members, hint, description=f"JPEG member for {answer_id}"
        )
        width, height = jpeg_sof_dimensions(image)
        # The field asks for the SOF pixel dimensions as a compact width-by-height pair.
        value = f"{width}x{height}"
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {member_path} from the assigned ZIP using the question hint, "
            f"then read the width and height directly from its JPEG SOF segment "
            f"({width} by {height} pixels)."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Read pixel dimensions from assigned JPEG structure")


if __name__ == "__main__":
    main()
