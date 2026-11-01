#!/usr/bin/env python3
"""Read allocated EVTX record counts from assigned Windows event logs."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    hinted_member,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


RECORD_COUNT = re.compile(r"(?m)^\s*Number of records\s*:\s*(\d+)\s*$")


def evtx_record_count(data: bytes, label: str) -> tuple[int, str]:
    if not data.startswith(b"ElfFile\x00"):
        raise SolverError(f"{label}: hinted member does not have EVTX file-header bytes")
    executable = shutil.which("evtxinfo")
    if executable is None:
        raise SolverError("The required evtxinfo parser is not installed")

    try:
        with tempfile.NamedTemporaryFile(suffix=".evtx") as source:
            source.write(data)
            source.flush()
            completed = subprocess.run(
                [executable, source.name],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SolverError(f"{label}: evtxinfo could not parse the assigned bytes") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SolverError(
            f"{label}: evtxinfo failed to parse the assigned bytes"
            + (f" ({detail})" if detail else "")
        )
    matches = RECORD_COUNT.findall(completed.stdout)
    if len(matches) != 1:
        raise SolverError(f"{label}: evtxinfo did not return one record count")
    count = int(matches[0])
    return count, (
        f"parsed the EVTX file with evtxinfo and read its allocated "
        f"'Number of records' value ({count})"
    )


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    members = [
        member
        for path, data in load_artifacts(artifact_paths)
        for member in iter_zip_files(data, path.name)
    ]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}

    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = hinted_member(question)
        if hint is None:
            raise SolverError(f"{answer_id}: no EVTX member hint was returned")
        label, data = unique_by_hint(
            members, hint, description=f"EVTX member for {answer_id}"
        )
        count, detail = evtx_record_count(data, label)
        value = str(count)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = f"{label}: {detail}"
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Count allocated records in the hinted EVTX file")


if __name__ == "__main__":
    main()
