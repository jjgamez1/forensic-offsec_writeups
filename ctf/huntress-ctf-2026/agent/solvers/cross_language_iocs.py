#!/usr/bin/env python3
"""Read cross-language IOC descriptors from static script artifacts."""

from __future__ import annotations

import ast
import base64
import json
import pathlib
import re
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)
from agent.solvers.host_with_the_most import collect_members
from agent.solvers.node_operation_graphs import solve_detailed as solve_node_bundle


TAG_RE = re.compile(
    r"HUNTRESS_ANALYSIS_V1:(HEX|B64|HB64|FRAG)-([A-Za-z0-9+/=.-]+)"
)
FIELD_SUFFIXES = (
    "stage-count",
    "host-profile",
    "obfuscation",
    "stage-profile",
    "next-language",
    "file-path",
    "adapter",
    "campaign",
    "attack",
    "role",
    "steps",
    "url",
)


def _decode_tagged_member(source: str, label: str) -> dict[str, Any]:
    matches = list(TAG_RE.finditer(source))
    if len(matches) != 1:
        raise SolverError(f"{label}: expected one HUNTRESS_ANALYSIS_V1 marker")
    encoding, encoded_text = matches[0].groups()
    try:
        if encoding == "HEX":
            decoded = bytes.fromhex(encoded_text)
        elif encoding == "B64":
            decoded = base64.b64decode(encoded_text, validate=True)
        elif encoding == "HB64":
            decoded = base64.b64decode(bytes.fromhex(encoded_text), validate=True)
        else:
            fragments = encoded_text.split(".")
            if any(not fragment or not re.fullmatch(r"[0-9a-fA-F]+", fragment) for fragment in fragments):
                raise ValueError("fragment list is malformed")
            decoded = bytes.fromhex("".join(fragments))
    except (ValueError, base64.binascii.Error) as exc:
        raise SolverError(f"{label}: tagged descriptor encoding is malformed") from exc
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: decoded descriptor is not UTF-8") from exc
    fields: dict[str, Any] = {}
    for item in text.split("|"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        fields[key] = value
    if fields.get("v") != "3" or "steps" not in fields:
        raise SolverError(f"{label}: decoded marker is not a version 3 IOC descriptor")
    steps = fields["steps"].split(",")
    if not steps or any(not step for step in steps):
        raise SolverError(f"{label}: decoded ordered steps are malformed")
    fields["steps"] = steps
    return fields


def _answer_field(answer_id: str) -> str:
    for suffix in FIELD_SUFFIXES:
        if answer_id.endswith("-" + suffix):
            return suffix
    raise SolverError(f"{answer_id}: unsupported polyglot/host field")


def _value(answer_id: str, descriptor: dict[str, Any]) -> str:
    suffix = _answer_field(answer_id)
    mapping = {
        "role": "role",
        "attack": "attack",
        "adapter": "adapter",
        "campaign": "campaign_id",
        "url": "url",
        "file-path": "file_path",
        "stage-count": "stage_count",
        "steps": "steps",
        "host-profile": "host_profile",
        "obfuscation": "obfuscation_profile",
        "stage-profile": "stage_profile",
        "next-language": "next_language",
    }
    key = mapping[suffix]
    value = descriptor.get(key)
    if suffix == "steps":
        value = ">".join(value) if isinstance(value, list) else value
    if value is None or value == "":
        raise SolverError(f"{answer_id}: decoded IOC descriptor lacks {key!r}")
    return str(value)


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    tagged_ids = [
        answer_id
        for answer_id in answer_ids
        if answer_id.startswith(("polyglot-", "host-"))
    ]
    delegated_ids = [answer_id for answer_id in answer_ids if answer_id not in tagged_ids]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}

    if delegated_ids:
        subset = dict(start)
        subset["answer_ids"] = delegated_ids
        subset["questions"] = [questions[item] for item in delegated_ids]
        delegated_answers, delegated_reasoning, _ = solve_node_bundle(
            subset, artifact_paths
        )
        answers.update(delegated_answers)
        reasoning.update(delegated_reasoning)

    if tagged_ids:
        members, _ = collect_members(artifact_paths)
        cache: dict[str, dict[str, Any]] = {}
        for answer_id in tagged_ids:
            question = questions[answer_id]
            hint = artifact_hint(question)
            if "->" not in hint:
                raise SolverError(f"{answer_id}: exact artifact member hint is missing")
            member_hint = hint.rsplit("->", 1)[-1].strip().replace("\\", "/")
            label, data = unique_by_hint(
                members, member_hint, description=f"tagged IOC member for {answer_id}"
            )
            if label not in cache:
                try:
                    source = data.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise SolverError(f"{label}: marked source is not UTF-8") from exc
                cache[label] = _decode_tagged_member(source, label)
            value = _value(answer_id, cache[label])
            validate_answer_format(answer_id, value, question)
            answers[answer_id] = value
            reasoning[answer_id] = (
                f"Selected {label} from the question's artifact hint, decoded its "
                "literal analysis marker, and returned the requested descriptor field."
            )
    if set(answers) != set(answer_ids):
        raise SolverError("Cross-language IOC solver did not produce every requested field")
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Decode the cross-language IOC specimen bundle")


if __name__ == "__main__":
    main()
