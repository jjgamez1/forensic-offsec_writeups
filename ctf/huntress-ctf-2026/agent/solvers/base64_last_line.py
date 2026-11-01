#!/usr/bin/env python3
"""Decode the assigned Base64 text and extract the answer requested by its format."""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import json
import pathlib
import re
from typing import Any
from urllib.parse import unquote_to_bytes

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


SLUG_PATTERN = re.compile(r"[a-z]+(?:-[a-z]+){2}-\d{2}")


def decode_payload(data: bytes) -> str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SolverError("The assigned Base64 artifact is not UTF-8 text") from exc
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise SolverError("The assigned text has no non-empty lines")

    numbered = [line for line in lines if re.match(r"^\d{2}\t", line)]
    if numbered:
        if len(numbered) != len(lines):
            raise SolverError("Numbered transformation input contains an unnumbered line")
        expected_stages = [f"{index:02d}" for index in range(1, len(numbered) + 1)]
        actual_stages = [line.split("\t", 1)[0] for line in numbered]
        if actual_stages != expected_stages:
            raise SolverError("Numbered transformation stages are missing or out of order")
        decoded_stages = []
        for line in numbered:
            stage, raw_value = line.split("\t", 1)
            value = raw_value if stage == "02" else raw_value.strip()
            try:
                if stage == "01":
                    padded = value + ("=" * (-len(value) % 4))
                    decoded = base64.b64decode(padded, validate=True).decode("utf-8")
                elif stage == "02":
                    decoded = codecs.decode(value, "rot_13")
                elif stage == "03":
                    decoded = bytes.fromhex(value).decode("utf-8")
                elif stage == "04":
                    groups = value.split()
                    if not groups or any(
                        not re.fullmatch(r"[01]{8}", group) for group in groups
                    ):
                        raise ValueError("binary stage is not a sequence of byte groups")
                    decoded = bytes(int(group, 2) for group in groups).decode("utf-8")
                elif stage == "05":
                    octets = [int(item, 10) for item in value.split()]
                    if not octets or any(item < 0 or item > 255 for item in octets):
                        raise ValueError("decimal stage contains a non-byte value")
                    decoded = bytes(octets).decode("utf-8")
                elif stage == "06":
                    octets = [int(item, 8) for item in value.split()]
                    if not octets or any(item < 0 or item > 255 for item in octets):
                        raise ValueError("octal stage contains a non-byte value")
                    decoded = bytes(octets).decode("utf-8")
                elif stage == "07":
                    decoded = unquote_to_bytes(value).decode("utf-8")
                elif stage == "08":
                    decoded = html.unescape(value)
                elif stage == "09":
                    decoded = json.loads(value)
                    if not isinstance(decoded, str):
                        raise ValueError("JSON stage is not a string")
                elif stage == "10":
                    padded = value.upper() + ("=" * (-len(value) % 8))
                    decoded = base64.b32decode(padded, casefold=True).decode("utf-8")
                elif stage == "11":
                    padded = value + ("=" * (-len(value) % 4))
                    decoded = base64.b64decode(padded, validate=True).decode("utf-8")
                else:
                    raise SolverError(f"Unsupported numbered transformation stage {stage}")
            except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
                raise SolverError(
                    f"Numbered transformation stage {stage} is malformed"
                ) from exc
            decoded_stages.append(decoded)
        return "".join(decoded_stages)

    encoded = None
    for line in reversed(lines):
        suffix = re.search(r"([A-Za-z0-9+/]+={0,2})\s*$", line)
        if not suffix:
            continue
        candidate = suffix.group(1)
        try:
            # RFC 4648 permits omitted trailing padding when the encoded
            # length makes the decoded byte count unambiguous.
            padded = candidate + ("=" * (-len(candidate) % 4))
            decoded = base64.b64decode(padded, validate=True)
            decoded_text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded_text.strip():
            encoded = decoded_text
            break
    if encoded is None:
        raise SolverError("No valid Base64 payload was found in the assigned text")
    return encoded


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    artifacts = load_artifacts(artifact_paths)
    question_delivery_refs = {
        answer_id: (
            max(0, int(match.group(1)) - 1)
            if (
                match := re.search(
                    r"\bdelivery\s+(\d+)\b",
                    artifact_hint(questions[answer_id]),
                    re.IGNORECASE,
                )
            )
            else None
        )
        for answer_id in answer_ids
    }
    ordered_delivery_refs = sorted(
        {ref for ref in question_delivery_refs.values() if ref is not None}
    )
    if ordered_delivery_refs and len(ordered_delivery_refs) != len(artifacts):
        raise SolverError(
            "Cannot map the downloaded artifacts to the current questions' delivery references"
        )

    payloads_by_artifact = [
        list(iter_zip_files(data, path.name))
        for path, data in artifacts
    ]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = hinted_member(question) or artifact_hint(question).strip()
        delivery_ref = question_delivery_refs[answer_id]
        scoped_payloads = [
            payload
            for group in payloads_by_artifact
            for payload in group
        ]
        if len(artifacts) > 1:
            if delivery_ref is not None:
                artifact_index = ordered_delivery_refs.index(delivery_ref)
                scoped_payloads = payloads_by_artifact[artifact_index]
            elif not hint:
                raise SolverError(
                    f"{answer_id}: no artifact hint identifies its assigned blob"
                )

        if hint:
            try:
                label, selected_payload = unique_by_hint(
                    scoped_payloads,
                    hint,
                    description=f"assigned blob for {answer_id}",
                )
            except SolverError:
                if len(scoped_payloads) != 1:
                    raise
                label, selected_payload = scoped_payloads[0]
        elif len(scoped_payloads) == 1:
            label, selected_payload = scoped_payloads[0]
        else:
            raise SolverError(f"{answer_id}: no artifact hint identifies its assigned blob")

        decoded = decode_payload(selected_payload)
        lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        if not lines:
            raise SolverError(f"{answer_id}: decoded artifact has no non-empty lines")
        matches = list(SLUG_PATTERN.finditer(lines[-1]))
        if len(matches) != 1:
            raise SolverError(
                f"{answer_id}: the final decoded line does not contain exactly one "
                "format-matching slug"
            )
        answer = matches[0].group(0)
        validate_answer_format(answer_id, answer, question)
        answers[answer_id] = answer
        reasoning[answer_id] = (
            f"Selected {label} using this question's artifact hint, decoded its "
            "complete transformation sequence, and extracted the unique slug from "
            "the final non-empty decoded line."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    """Return answers keyed by the exact IDs in this start response."""
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Analyze an assigned Base64 warmup artifact")


if __name__ == "__main__":
    main()
