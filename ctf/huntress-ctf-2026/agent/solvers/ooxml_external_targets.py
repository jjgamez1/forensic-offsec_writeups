#!/usr/bin/env python3
"""Read external relationship targets from assigned OOXML documents."""

from __future__ import annotations

import io
import json
import pathlib
import zipfile
from typing import Any
from xml.etree import ElementTree

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


def _ooxml_members(
    artifact_paths: list[pathlib.Path],
) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []

    def expand(data: bytes, label: str, depth: int = 0) -> None:
        if depth > 8:
            raise SolverError("Nested ZIP depth exceeds the static inspection limit")
        if pathlib.PurePosixPath(label).suffix.casefold() in {".docx", ".pptx", ".xlsx"}:
            members.append((label, data))
            return
        if not data.startswith(b"PK\x03\x04"):
            members.append((label, data))
            return
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                entries = [(info.filename, archive.read(info)) for info in infos]
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise SolverError(f"{label}: assigned ZIP could not be read") from exc
        for name, payload in entries:
            expand(payload, f"{label}/{name}", depth + 1)

    for path, payload in load_artifacts(artifact_paths):
        expand(payload, path.name)
    return members


def _external_targets(data: bytes, label: str) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as document:
            rels = [
                info for info in document.infolist()
                if not info.is_dir()
                and info.filename.casefold().endswith(".rels")
            ]
            if not rels:
                raise SolverError(f"{label}: OOXML package has no relationship parts")
            targets: list[str] = []
            for info in rels:
                try:
                    root = ElementTree.fromstring(document.read(info))
                except (ElementTree.ParseError, OSError, RuntimeError) as exc:
                    raise SolverError(
                        f"{label}/{info.filename}: malformed OOXML relationships"
                    ) from exc
                for relationship in root:
                    if relationship.attrib.get("TargetMode") == "External":
                        target = relationship.attrib.get("Target")
                        if target is None:
                            raise SolverError(
                                f"{label}/{info.filename}: external relationship has no Target"
                            )
                        targets.append(target)
            return targets
    except (OSError, zipfile.BadZipFile) as exc:
        raise SolverError(f"{label}: assigned OOXML document is not a readable ZIP") from exc


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    members = _ooxml_members(artifact_paths)
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}

    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = artifact_hint(question).strip()
        member_hint = hint.rsplit("->", 1)[-1].strip() if hint else ""
        if not member_hint:
            raise SolverError(f"{answer_id}: question has no document artifact hint")
        label, document = unique_by_hint(
            members,
            member_hint,
            description=f"OOXML document for {answer_id}",
        )
        _, field = parse_answer_id(answer_id)
        if field not in {
            "d15-ooxml-001-ooxml-external-relationship-targets",
            "ooxml_external_relationship_targets",
        }:
            raise SolverError(f"{answer_id}: unsupported OOXML answer field")
        value = json.dumps(_external_targets(document, label), separators=(",", ":"))
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"{label}: parsed every .rels part in package order and retained "
            "Target attributes whose TargetMode is External, in relationship order"
        )

    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Extract external relationship targets from assigned OOXML")


if __name__ == "__main__":
    main()
