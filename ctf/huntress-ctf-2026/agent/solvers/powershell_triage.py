#!/usr/bin/env python3
"""Statically triage assigned PowerShell samples without executing them."""

from __future__ import annotations

import base64
import json
import pathlib
import re
import zipfile
from io import BytesIO
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    hinted_member,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


ARCHIVE_PASSWORD = "infected"
SCENARIO_TECHNIQUE = {
    "resource_hijacking": "T1496",
    "synthetic_collection": "T1555.003",
    "synthetic_impact": "T1486",
}


def read_archive(data: bytes, label: str, password: str) -> list[tuple[str, bytes]]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            encrypted = any(info.flag_bits & 1 for info in infos)
    except zipfile.BadZipFile:
        return [(label, data)]

    if encrypted:
        try:
            import pyzipper
        except ImportError as exc:
            raise SolverError(
                "This assigned AES-encrypted ZIP requires pyzipper, which is not "
                "installed in the active Python environment. No package was fetched "
                "or installed."
            ) from exc
        try:
            with pyzipper.AESZipFile(BytesIO(data)) as archive:
                archive.pwd = password.encode("utf-8")
                return [
                    (f"{label}/{info.filename}", archive.read(info))
                    for info in archive.infolist()
                    if not info.is_dir()
                ]
        except (RuntimeError, ValueError, OSError) as exc:
            raise SolverError(f"Could not read assigned encrypted ZIP {label}") from exc

    with zipfile.ZipFile(BytesIO(data)) as archive:
        return [
            (f"{label}/{info.filename}", archive.read(info))
            for info in archive.infolist()
            if not info.is_dir()
        ]


def decode_descriptor(source: str, filename: str) -> tuple[dict[str, Any], set[str]]:
    match = re.search(
        r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)",
        source,
        flags=re.IGNORECASE,
    )
    if not match:
        raise SolverError(f"{filename}: no embedded Base64 descriptor was found")
    try:
        decoded = base64.b64decode(match.group(1), validate=True).decode("utf-8")
        descriptor = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError(
            f"{filename}: embedded descriptor is not valid Base64 JSON"
        ) from exc
    if not isinstance(descriptor, dict):
        raise SolverError(f"{filename}: decoded descriptor is not a JSON object")

    native_types = {
        item.lower()
        for item in re.findall(r"\[([A-Za-z][A-Za-z0-9_.]+)\]", source)
    }
    return descriptor, native_types


def classify(descriptor: dict[str, Any], native_types: set[str]) -> dict[str, Any]:
    collection = descriptor.get("c")
    if (
        isinstance(collection, str)
        and collection.lower().startswith("wallet_")
        and any("diagnostics.process" in item for item in native_types)
    ):
        scenario = "resource_hijacking"
        indicators = {
            "url": descriptor.get("b"),
            "wallet": collection,
            "mutex": descriptor.get("h"),
        }
    elif (
        isinstance(descriptor.get("b"), str)
        and descriptor["b"].startswith(".")
        and isinstance(collection, str)
        and collection.lower().startswith("recovery-")
        and any("security.cryptography.aes" in item for item in native_types)
    ):
        scenario = "synthetic_impact"
        indicators = {
            "extension": descriptor.get("b"),
            "recovery_note": collection,
            "url": descriptor.get("d"),
        }
    elif (
        isinstance(collection, list)
        and any(str(item).lower() in {"login data", "cookies"} for item in collection)
        and any("compression.zipfile" in item for item in native_types)
    ):
        scenario = "synthetic_collection"
        indicators = {
            "url": descriptor.get("b"),
            "first_filename": next(
                (item for item in collection if isinstance(item, str)), None
            ),
            "user_agent": descriptor.get("f"),
        }
    else:
        raise SolverError(
            "Could not classify the sample using its decoded descriptor and "
            "PowerShell type references"
        )

    if any(value is None for value in indicators.values()):
        raise SolverError(f"The {scenario} descriptor is missing a requested indicator")
    return {
        "scenario": scenario,
        "attack": SCENARIO_TECHNIQUE[scenario],
        **indicators,
    }


def answer_semantic(question: dict[str, Any], answer_id: str) -> str:
    text = str(question.get("question", "")).lower()
    field = answer_id.rsplit("-", 1)[-1].lower()
    if "scenario best describes" in text or field == "scenario":
        return "scenario"
    if "mitre" in text or "technique" in text or field in {"attack", "technique"}:
        return "attack"
    if "user-agent" in text or "user agent" in text or field in {"user-agent", "user_agent"}:
        return "user_agent"
    if "filename" in text or field in {"file", "filename"}:
        if "recovery" in text or "recovery" in field:
            return "recovery_note"
        return "first_filename"
    for token, semantic in (
        ("wallet", "wallet"),
        ("mutex", "mutex"),
        ("extension", "extension"),
        ("url", "url"),
        ("recovery-note", "recovery_note"),
    ):
        if token in text or token in field:
            return semantic
    raise SolverError(f"Cannot identify the requested PowerShell indicator: {answer_id}")


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    loaded = load_artifacts(artifact_paths)
    all_files: list[tuple[str, bytes]] = []
    for path, data in loaded:
        all_files.extend(read_archive(data, path.name, ARCHIVE_PASSWORD))

    sample_answers: dict[str, dict[str, Any]] = {}
    sample_sources: dict[str, str] = {}
    for answer_id, question in questions.items():
        hint = hinted_member(question)
        if not hint:
            raise SolverError(f"{answer_id}: question has no sample member reference")
        source_path, source_bytes = unique_by_hint(
            all_files, hint, description="PowerShell sample"
        )
        if source_path not in sample_answers:
            try:
                source = source_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SolverError(f"{source_path}: sample is not UTF-8 text") from exc
            descriptor, native_types = decode_descriptor(source, source_path)
            sample_answers[source_path] = classify(descriptor, native_types)
            sample_sources[source_path] = source_path

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id, question in questions.items():
        hint = hinted_member(question)
        source_path, _ = unique_by_hint(
            all_files, hint or "", description="PowerShell sample"
        )
        semantic = answer_semantic(question, answer_id)
        values = sample_answers[source_path]
        value = values.get(semantic)
        if not isinstance(value, str) or not value:
            raise SolverError(f"{answer_id}: artifact does not determine {semantic}")
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Statically decoded the descriptor and inspected type references in "
            f"{sample_sources[source_path]}; classified its behavior and derived "
            f"the requested {semantic} field."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    """Return answers keyed by the exact IDs in this start response."""
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically analyze assigned PowerShell sample artifacts")


if __name__ == "__main__":
    main()
