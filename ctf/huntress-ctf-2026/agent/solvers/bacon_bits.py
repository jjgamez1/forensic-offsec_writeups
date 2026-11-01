#!/usr/bin/env python3
"""Decode five-a/b Bacon nibble tokens in the assigned warmup artifact."""

from __future__ import annotations

import pathlib
import re
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
from agent.solvers.rail_fence_warmup import _decode_stage


def _decode_blob(data: bytes, label: str) -> tuple[str, str]:
    try:
        encoded = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: assigned blob is not UTF-8 text") from exc
    lines = [line for line in encoded.splitlines() if line.strip()]
    fragments = []
    for line in lines:
        match = re.fullmatch(r"(\d{2})\t(.*)", line)
        if match is None:
            fragments = []
            break
        fragments.append((int(match.group(1)), match.group(2)))
    if fragments:
        actual = [number for number, _ in fragments]
        if actual != list(range(1, len(actual) + 1)) or actual[-1] < 17:
            raise SolverError(f"{label}: numbered transformations are missing or out of order")
        decoded = "".join(
            _decode_stage(number, fragment, label)
            for number, fragment in fragments
        )
        method = f"numbered warmup encoding fragments through stage {actual[-1]:02d}"
    else:
        tokens = encoded.split()
        if not tokens or not all(re.fullmatch(r"[ab]{5}", token) for token in tokens):
            raise SolverError(f"{label}: expected a/b tokens or numbered warmup fragments")
        nibbles = []
        for token in tokens:
            number = int(token.translate(str.maketrans({"a": "0", "b": "1"})), 2)
            if number > 15:
                raise SolverError(f"{label}: five-letter token exceeds a hexadecimal nibble")
            nibbles.append(f"{number:x}")
        hexadecimal = "".join(nibbles)
        if len(hexadecimal) % 2:
            raise SolverError(f"{label}: decoded hexadecimal has an odd number of nibbles")
        try:
            decoded = bytes.fromhex(hexadecimal).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SolverError(f"{label}: decoded hexadecimal is not UTF-8 text") from exc
        method = "five a/b bits per hexadecimal nibble"
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        raise SolverError(f"{label}: decoded blob has no nonempty line")
    final_line = lines[-1]
    slugs = re.findall(r"\b[a-z]+(?:-[a-z]+){2}-\d{2}\b", final_line)
    if len(slugs) != 1:
        raise SolverError(f"{label}: final decoded line does not contain exactly one answer slug")
    slug = slugs[0]
    trailing = final_line[final_line.find(slug) + len(slug) :].strip()
    if trailing:
        colon = final_line.rfind(":")
        instructed = final_line[colon + 1 :].strip() if colon >= 0 else ""
        if not instructed.startswith(slug) or instructed == slug:
            raise SolverError(f"{label}: cannot isolate the full instructed answer after its slug")
        return instructed, f"{method}; full instructed token {instructed!r}"
    return slug, f"{method}; final decoded line contains only the slug"


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    loaded = load_artifacts(artifact_paths)
    groups: list[list[tuple[str, bytes]]] = [
        list(iter_zip_files(data, path.name)) for path, data in loaded
    ]
    all_members = [member for group in groups for member in group]
    answers: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for answer_id in answer_ids:
        hint = artifact_hint(questions[answer_id]).replace("\\", "/").strip()
        delivery_match = re.search(r"\bdelivery\s+(\d+)\b", hint, re.IGNORECASE)
        scoped = all_members
        if delivery_match and len(groups) > 1:
            index = int(delivery_match.group(1)) - 1
            if not 0 <= index < len(groups):
                raise SolverError(f"{answer_id}: artifact hint names an unassigned delivery")
            scoped = groups[index]
        member_hint = hint
        if delivery_match:
            member_hint = re.sub(
                r"(?i)^delivery\s+\d+\s*(?:->|:|/)\s*", "", member_hint
            ).strip()
        if "->" in member_hint:
            member_hint = member_hint.rsplit("->", 1)[1].strip()
        if member_hint:
            try:
                label, content = unique_by_hint(
                    scoped, member_hint, description=f"assigned blob for {answer_id}"
                )
            except SolverError:
                if (
                    len(loaded) != 1
                    or loaded[0][1].startswith(b"PK\x03\x04")
                ):
                    raise
                label, content = loaded[0][0].name, loaded[0][1]
        elif len(scoped) == 1:
            label, content = scoped[0]
        else:
            raise SolverError(f"{answer_id}: no artifact hint selects one assigned blob")
        answers[answer_id], method = _decode_blob(content, label)
        evidence[answer_id] = f"{label}: {method}"
        validate_answer_format(answer_id, answers[answer_id], questions[answer_id])
    return answers, evidence, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Decode the assigned five-a/b warmup artifact")


if __name__ == "__main__":
    main()
