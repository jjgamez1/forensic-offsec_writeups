#!/usr/bin/env python3
"""Reverse the assigned warmup text and extract its final-line answer slug."""

from __future__ import annotations

import pathlib
import re
import base64
import codecs
import html
import json
import urllib.parse
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


SLUG = re.compile(r"\b[a-z]+(?:-[a-z]+){2}-\d{2}\b")


def _caesar_backward_seven(text: str) -> str:
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    source = lowercase + uppercase
    shifted = lowercase[-7:] + lowercase[:-7]
    shifted += uppercase[-7:] + uppercase[:-7]
    return text.translate(str.maketrans(source, shifted))


def _rot47(text: str) -> str:
    return "".join(
        chr(33 + ((ord(char) - 33 + 47) % 94))
        if 33 <= ord(char) <= 126
        else char
        for char in text
    )


def _decode(data: bytes, label: str, transform: str) -> tuple[str, str]:
    try:
        raw_text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: assigned warmup blob is not UTF-8") from exc
    raw_lines = [line for line in raw_text.splitlines() if line.strip()]
    tagged: list[tuple[int, str]] = []
    for line in raw_lines:
        match = re.fullmatch(r"(\d{2})\t(.*)", line)
        if match is None:
            tagged = []
            break
        tagged.append((int(match.group(1)), match.group(2).strip()))
    if tagged:
        expected = list(range(1, len(tagged) + 1))
        actual = [number for number, _ in tagged]
        if actual != expected:
            raise SolverError(f"{label}: numbered transformations are missing or out of order")
        parts: list[str] = []
        for number, encoded in tagged:
            try:
                if number == 1:
                    part = base64.b64decode(encoded, validate=True).decode("utf-8")
                elif number == 2:
                    part = codecs.decode(encoded, "rot_13")
                elif number == 3:
                    part = bytes.fromhex(encoded).decode("utf-8")
                elif number == 4:
                    values = [int(token, 2) for token in encoded.split()]
                    part = bytes(values).decode("utf-8")
                elif number == 5:
                    values = [int(token, 10) for token in encoded.split()]
                    part = bytes(values).decode("utf-8")
                elif number == 6:
                    values = [int(token, 8) for token in encoded.split()]
                    part = bytes(values).decode("utf-8")
                elif number == 7:
                    part = urllib.parse.unquote_to_bytes(encoded).decode("utf-8")
                elif number == 8:
                    part = html.unescape(encoded)
                elif number == 9:
                    part = json.loads(encoded)
                    if not isinstance(part, str):
                        raise ValueError("JSON fragment is not a string")
                elif number == 10:
                    part = base64.b32decode(encoded, casefold=False).decode("utf-8")
                elif number == 11:
                    padded = encoded + ("=" * (-len(encoded) % 4))
                    part = base64.b64decode(padded, validate=True).decode("utf-8")
                elif number == 12:
                    part = encoded[::-1]
                elif number == 13:
                    table = str.maketrans(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                        "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
                    )
                    part = encoded.translate(table)
                elif number == 14:
                    part = _caesar_backward_seven(encoded)
                elif number == 15:
                    part = _rot47(encoded)
                else:
                    raise SolverError(f"{label}: unsupported numbered stage {number:02d}")
            except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
                raise SolverError(f"{label}: numbered stage {number:02d} is malformed") from exc
            parts.append(part)
        decoded = "".join(parts)
        method = (
            "numbered Base64, ROT13, hex, binary, decimal, octal, percent, HTML, "
            "JSON, Base32, padded Base64, reversal, Atbash, Caesar-7, and ROT47 stages"
        )
    else:
        if transform == "atbash":
            table = str.maketrans(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
            )
            decoded = raw_text.translate(table)
            method = "applied the Atbash alphabet substitution"
        elif transform == "rot47":
            decoded = _rot47(raw_text)
            method = "rotated printable ASCII characters by 47 positions"
        elif transform == "caesar-7":
            decoded = _caesar_backward_seven(raw_text)
            method = "applied a seven-place backward Caesar shift"
        else:
            decoded = raw_text.strip()[::-1]
            method = "reversed the exact UTF-8 text"
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        raise SolverError(f"{label}: decoded warmup blob has no nonempty lines")
    matches = SLUG.findall(lines[-1])
    if len(matches) != 1:
        raise SolverError(
            f"{label}: final decoded line does not contain exactly one answer slug"
        )
    return matches[0], f"{method}; selected its final nonempty line"


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    challenge_text = f"{start.get('name', '')} {start.get('prompt', '')}".casefold()
    if "opposite" in challenge_text or "a met z" in challenge_text:
        transform = "atbash"
    elif "forty-seven" in challenge_text or "punctuation went for a spin" in challenge_text:
        transform = "rot47"
    elif "caesar" in challenge_text and "week off" in challenge_text:
        transform = "caesar-7"
    else:
        transform = "reverse"
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
            if len(members) != 1:
                raise SolverError(f"{answer_id}: no hint selects one warmup blob")
            label, data = members[0]
        else:
            member_hint = hint.rsplit("->", 1)[-1].strip()
            try:
                label, data = unique_by_hint(
                    members, member_hint, description=f"warmup blob for {answer_id}"
                )
            except SolverError:
                if len(members) != 1 or len(artifact_paths) != 1:
                    raise
                label, data = members[0]
        value, detail = _decode(data, label, transform)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = f"{label}: {detail}"
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Reverse an assigned warmup text artifact")


if __name__ == "__main__":
    main()
