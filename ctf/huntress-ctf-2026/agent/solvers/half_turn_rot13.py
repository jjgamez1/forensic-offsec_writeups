#!/usr/bin/env python3
"""Decode the assigned UTF-8 text with ROT13 and extract its final answer slug."""

from __future__ import annotations

import codecs
import pathlib
import re
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

    payloads: list[tuple[str, bytes]] = []
    payloads_by_artifact: list[list[tuple[str, bytes]]] = []
    for path, data in artifacts:
        contents = list(iter_zip_files(data, path.name))
        payloads_by_artifact.append(contents)
        payloads.extend(contents)
    if not payloads:
        raise SolverError("No files were found in the assigned artifact bytes")

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = hinted_member(question) or artifact_hint(question).strip()
        delivery_ref = question_delivery_refs[answer_id]
        scoped_payloads = payloads
        if len(artifacts) > 1:
            if delivery_ref is not None:
                artifact_index = ordered_delivery_refs.index(delivery_ref)
                scoped_payloads = payloads_by_artifact[artifact_index]
            elif not hint:
                raise SolverError(
                    f"{answer_id}: question does not identify its artifact or delivery"
                )

        if hint:
            try:
                _, selected_payload = unique_by_hint(
                    scoped_payloads,
                    hint,
                    description=f"artifact for {answer_id}",
                )
            except SolverError:
                if len(scoped_payloads) == 1:
                    selected_payload = scoped_payloads[0][1]
                else:
                    raise
        elif len(scoped_payloads) == 1:
            selected_payload = scoped_payloads[0][1]
        else:
            raise SolverError(f"{answer_id}: no artifact hint was returned")

        try:
            encoded_text = selected_payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise SolverError(
                f"{answer_id}: the assigned artifact member is not UTF-8 text"
            ) from exc
        decoded_text = codecs.decode(encoded_text, "rot_13")
        final_lines = [
            line.strip()
            for line in decoded_text.splitlines()
            if line.strip()
        ]
        if not final_lines:
            raise SolverError(f"{answer_id}: decoded artifact has no non-empty lines")
        answer = final_lines[-1].rsplit(":", 1)[-1].strip()
        try:
            validate_answer_format(answer_id, answer, question)
        except SolverError as exc:
            raise SolverError(
                f"{answer_id}: final decoded line does not satisfy the returned format"
            ) from exc
        answers[answer_id] = answer
        reasoning[answer_id] = (
            "Resolved the member named by this question's current artifact hint, applied ROT13 "
            "to its UTF-8 text, selected the final non-empty decoded line, extracted its "
            "final colon-delimited value, and checked the returned format."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    """Return the answer under the exact answer ID supplied by this attempt."""
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Analyze a Half a Turn text artifact")


if __name__ == "__main__":
    main()
