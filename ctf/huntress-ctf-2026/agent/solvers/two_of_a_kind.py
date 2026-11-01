#!/usr/bin/env python3
"""Decode byte-per-token binary warmup text and extract its instructed slug."""

from __future__ import annotations

import pathlib
import re
import base64
import codecs
import urllib.parse
from typing import Any

from agent.solvers.common import (
    SolverError,
    artifact_hint,
    answer_ids_and_replay,
    hinted_member,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


def decode_binary_text(data: bytes, answer_id: str) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{answer_id}: encoded text is not ASCII") from exc

    numbered_lines = [line for line in text.splitlines() if line.strip()]
    if numbered_lines and all(re.match(r"^\d{2}\t", line) for line in numbered_lines):
        output = []
        for line in numbered_lines:
            stage, payload = line.split("\t", 1)
            try:
                if stage == "01":
                    payload += "=" * ((-len(payload.strip())) % 4)
                    decoded = base64.b64decode(payload.strip(), validate=True).decode("utf-8")
                elif stage == "02":
                    decoded = codecs.decode(payload, "rot_13")
                elif stage == "03":
                    decoded = bytes.fromhex(payload).decode("utf-8")
                elif stage == "04":
                    bits = payload.split()
                    if not bits or any(not re.fullmatch(r"[01]{8}", bit) for bit in bits):
                        raise ValueError("stage 04 is not byte-aligned binary")
                    decoded = bytes(int(bit, 2) for bit in bits).decode("utf-8")
                elif stage == "05":
                    codes = payload.split()
                    if not codes or any(not re.fullmatch(r"\d{1,3}", code) for code in codes):
                        raise ValueError("stage 05 is not whitespace-separated decimal bytes")
                    values = [int(code, 10) for code in codes]
                    if any(value > 255 for value in values):
                        raise ValueError("stage 05 byte is outside 0..255")
                    decoded = bytes(values).decode("utf-8")
                elif stage == "06":
                    codes = payload.split()
                    if not codes or any(not re.fullmatch(r"[0-7]{3}", code) for code in codes):
                        raise ValueError("stage 06 is not whitespace-separated octal bytes")
                    values = [int(code, 8) for code in codes]
                    if any(value > 255 for value in values):
                        raise ValueError("stage 06 byte is outside 0..377")
                    decoded = bytes(values).decode("utf-8")
                elif stage == "07":
                    encoded = payload.strip()
                    if not re.fullmatch(r"(?:%[0-9a-fA-F]{2})+", encoded):
                        raise ValueError("stage 07 is not a sequence of percent-encoded bytes")
                    decoded = urllib.parse.unquote_to_bytes(encoded).decode("utf-8")
                else:
                    raise SolverError(f"{answer_id}: unsupported numbered encoding stage {stage}")
            except (ValueError, UnicodeDecodeError) as exc:
                raise SolverError(
                    f"{answer_id}: numbered encoding stage {stage} is malformed"
                ) from exc
            output.append(decoded)
        return "".join(output)

    if re.fullmatch(r"(?:%[0-9a-fA-F]{2})+", text.strip()):
        try:
            return urllib.parse.unquote_to_bytes(text.strip()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{answer_id}: percent-encoded bytes are not UTF-8") from exc

    tokens = text.split()
    if tokens and all(re.fullmatch(r"[0-7]{3}", token) for token in tokens):
        try:
            return bytes(int(token, 8) for token in tokens).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{answer_id}: octal bytes are not UTF-8") from exc
    if tokens and all(re.fullmatch(r"\d{1,3}", token) for token in tokens):
        values = [int(token, 10) for token in tokens]
        if any(value > 255 for value in values):
            raise SolverError(f"{answer_id}: decimal byte value is outside 0..255")
        try:
            return bytes(values).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SolverError(f"{answer_id}: decimal bytes are not UTF-8") from exc
    if not tokens or any(not re.fullmatch(r"[01]{8}", token) for token in tokens):
        raise SolverError(
            f"{answer_id}: artifact is neither numbered text encoding nor "
            "whitespace-separated decimal bytes or 8-bit binary"
        )
    decoded = bytes(int(token, 2) for token in tokens)
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{answer_id}: decoded bytes are not UTF-8") from exc


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    artifacts = load_artifacts(artifact_paths)
    refs = {}
    for answer_id in answer_ids:
        match = re.search(
            r"\bdelivery\s+(\d+)\b",
            artifact_hint(questions[answer_id]),
            re.IGNORECASE,
        )
        refs[answer_id] = max(0, int(match.group(1)) - 1) if match else None
    ordered_refs = sorted({item for item in refs.values() if item is not None})
    if len(artifacts) > 1 and ordered_refs and len(ordered_refs) != len(artifacts):
        raise SolverError("Cannot map the assigned deliveries to the question hints")

    members_by_artifact = [
        list(iter_zip_files(data, path.name)) for path, data in artifacts
    ]
    all_members = [member for delivery in members_by_artifact for member in delivery]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = hinted_member(question)
        if hint is None:
            raw_hint = artifact_hint(question).strip()
            delivery_hint = re.match(
                r"(?is)^delivery\s+\d+\s*[:/]\s*(.+)$", raw_hint
            )
            if delivery_hint:
                hint = delivery_hint.group(1).strip()
            elif raw_hint and not re.fullmatch(r"delivery\s+\d+", raw_hint, re.I):
                hint = pathlib.PurePosixPath(
                    raw_hint.replace("\\", "/")
                ).name
        if len(artifacts) > 1:
            delivery_ref = refs[answer_id]
            if delivery_ref is not None:
                scoped_members = members_by_artifact[
                    ordered_refs.index(delivery_ref)
                ]
            else:
                scoped_members = all_members
        else:
            scoped_members = all_members
        if hint:
            try:
                _, payload = unique_by_hint(
                    scoped_members, hint, description=f"binary text for {answer_id}"
                )
            except SolverError:
                if len(scoped_members) == 1:
                    payload = scoped_members[0][1]
                else:
                    raise
        elif len(scoped_members) == 1:
            payload = scoped_members[0][1]
        else:
            raise SolverError(f"{answer_id}: no artifact hint selects one member")

        text = decode_binary_text(payload, answer_id)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise SolverError(f"{answer_id}: decoded artifact has no non-empty line")
        final_line = lines[-1]
        match = re.search(
            r"\bsubmit this exact answer to the Game Master:\s*([a-z]+(?:-[a-z]+){2}-\d{2})\s*$",
            final_line,
            re.IGNORECASE,
        )
        if not match:
            raise SolverError(
                f"{answer_id}: final decoded line does not contain the instructed answer slug"
            )
        value = match.group(1)
        validate_answer_format(answer_id, value, questions[answer_id])
        answers[answer_id] = value
        raw_text = payload.decode("ascii", errors="replace").split()
        numbered = [
            line.split("\t", 1)[0]
            for line in payload.decode("ascii", errors="replace").splitlines()
            if line.strip()
        ]
        if numbered and all(re.fullmatch(r"\d{2}", stage) for stage in numbered):
            encoding = f"numbered stages {', '.join(numbered)} (Base64, ROT13, hex, binary, decimal bytes)"
        elif raw_text and all(re.fullmatch(r"\d{1,3}", token) for token in raw_text):
            encoding = "whitespace-separated decimal byte values"
        else:
            encoding = "whitespace-separated 8-bit binary values"
        reasoning[answer_id] = (
            f"Decoded the assigned {encoding} as UTF-8, "
            f"selected the final non-empty line, and extracted its explicitly "
            f"instructed slug {value!r}."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Decode the assigned binary-text warmup")


if __name__ == "__main__":
    main()
