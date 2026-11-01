#!/usr/bin/env python3
"""Review changed solver code against saved attempts without contacting the Game Master."""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "agent"
REGISTRY_PATH = AGENT_DIR / "registry.json"
ARTIFACTS_DIR = AGENT_DIR / "artifacts"
RUNS_DIR = AGENT_DIR / "runs"
SOLVER_REVIEW_TIMEOUT_SECONDS = 120
sys.path.insert(0, str(ROOT))

from agent.solvers.common import (  # noqa: E402
    answer_ids_and_replay,
    load_start,
    questions_by_id,
    validate_answer_format,
)
from agent.runtime import configured_python  # noqa: E402


class ReviewError(RuntimeError):
    """A safe error that prevents solver approval."""


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_registry() -> dict[str, Any]:
    try:
        value = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewError(f"Cannot read solver registry: {REGISTRY_PATH}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("solvers"), list):
        raise ReviewError("Solver registry has no solvers array")
    return value


def find_solver(registry: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item
        for item in registry["solvers"]
        if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        raise ReviewError(f"Expected exactly one registry entry for solver {name!r}")
    return matches[0]


def run_solver(source: pathlib.Path, start_path: pathlib.Path, artifacts: list[pathlib.Path]) -> dict[str, Any]:
    command = [
        str(configured_python()),
        "-c",
        (
            "import runpy,sys; "
            "root,script,*args=sys.argv[1:]; "
            "sys.path.insert(0,root); "
            "sys.argv=[script,*args]; "
            "runpy.run_path(script,run_name='__main__')"
        ),
        str(ROOT),
        str(source),
        "--start",
        str(start_path),
    ]
    for path in artifacts:
        command.extend(("--artifact", str(path)))
    command.append("--dry-run")
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=SOLVER_REVIEW_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": (
                "solver timed out after "
                f"{SOLVER_REVIEW_TIMEOUT_SECONDS} seconds"
            ),
        }
    output = completed.stdout.strip()
    if completed.returncode != 0:
        try:
            error = json.loads(completed.stderr).get("error", completed.stderr.strip())
        except (json.JSONDecodeError, AttributeError):
            error = completed.stderr.strip() or f"solver exited {completed.returncode}"
        return {"ok": False, "error": str(error)}
    try:
        result = json.loads(output)
    except json.JSONDecodeError:
        return {"ok": False, "error": "solver dry-run did not return JSON"}
    if not isinstance(result, dict) or not isinstance(result.get("answers"), dict):
        return {"ok": False, "error": "solver dry-run returned no answers object"}
    return {"ok": True, **result}


def check_answers(start: dict[str, Any], result: dict[str, Any]) -> tuple[bool, str | None]:
    answers = result.get("answers")
    try:
        answer_ids, _ = answer_ids_and_replay(start)
    except Exception as exc:
        return False, str(exc)
    if not isinstance(answers, dict) or set(answers) != set(answer_ids):
        return False, "solver answers do not match the exact answer_ids"
    try:
        questions = questions_by_id(start, answer_ids)
        for answer_id in answer_ids:
            value = answers[answer_id]
            if not isinstance(value, str):
                raise ValueError(f"{answer_id}: answer is not a string")
            validate_answer_format(answer_id, value, questions[answer_id])
    except Exception as exc:
        return False, str(exc)
    return True, None


def saved_attempts(spec: dict[str, Any]) -> list[tuple[str, pathlib.Path, list[pathlib.Path]]]:
    result = []
    for challenge_id in spec.get("challenge_ids", []):
        challenge_dir = ARTIFACTS_DIR / str(challenge_id)
        if not challenge_dir.is_dir():
            continue
        for start_path in sorted(challenge_dir.glob("*/start.json")):
            attempt_dir = start_path.parent
            artifacts = sorted(attempt_dir.glob("artifact-*.bin"))
            if not artifacts:
                artifacts = sorted(attempt_dir.glob("artifact.bin"))
            if artifacts:
                result.append((str(challenge_id), start_path, artifacts))
    return result


def public_answers(start: dict[str, Any], answers: dict[str, Any]) -> dict[str, Any]:
    questions = {
        item.get("id"): item
        for item in start.get("questions", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    shown = {}
    for answer_id, value in answers.items():
        question = questions.get(answer_id, {})
        sensitive_text = (
            f"{answer_id} {question.get('question', '')}".casefold()
        )
        sensitive = "flag" in sensitive_text or "proof" in sensitive_text
        shown[answer_id] = "[stored privately]" if sensitive else value
    return shown


def accepted_attempt_records() -> tuple[set[str], dict[str, pathlib.Path]]:
    accepted: set[str] = set()
    latest_dry_runs: dict[str, tuple[str, pathlib.Path]] = {}
    for log_path in sorted(RUNS_DIR.glob("*.jsonl")):
        try:
            events = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, json.JSONDecodeError):
            continue
        for event in events:
            attempt_id = event.get("attempt_id")
            if not isinstance(attempt_id, str):
                continue
            if event.get("action") == "submission" and event.get("result") == "CORRECT":
                accepted.add(attempt_id)
            if event.get("action") == "solver_dry_run":
                report_ref = event.get("report")
                if isinstance(report_ref, str):
                    event_time = str(event.get("time", ""))
                    previous = latest_dry_runs.get(attempt_id)
                    if previous is None or event_time >= previous[0]:
                        latest_dry_runs[attempt_id] = (
                            event_time,
                            ROOT / report_ref,
                        )
    dry_run_reports = {
        attempt_id: report_path
        for attempt_id, (_, report_path) in latest_dry_runs.items()
    }
    return accepted, dry_run_reports


def accepted_answers_for_attempt(
    start: dict[str, Any],
    attempt_id: str,
    accepted_attempts: set[str],
    dry_run_reports: dict[str, pathlib.Path],
) -> dict[str, Any] | None:
    if attempt_id not in accepted_attempts:
        return None
    report_path = dry_run_reports.get(attempt_id)
    if report_path is None or not report_path.is_file():
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    answers = report.get("answers")
    if not isinstance(answers, dict):
        return None
    return public_answers(start, answers)


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def review_solver(name: str, *, print_diff: bool = True) -> pathlib.Path:
    registry = load_registry()
    spec = find_solver(registry, name)
    current = ROOT / str(spec.get("path", ""))
    approved_ref = spec.get("approved_source")
    if not current.is_file():
        raise ReviewError("Current solver source is missing")
    approved: pathlib.Path | None = None
    if isinstance(approved_ref, str):
        approved = ROOT / approved_ref
        if not approved.is_file():
            raise ReviewError("Approved source snapshot is missing")
        recorded_approved_hash = spec.get("approved_solver_sha256")
        if (
            not isinstance(recorded_approved_hash, str)
            or sha256_file(approved) != recorded_approved_hash
        ):
            raise ReviewError("Approved snapshot does not match the hash recorded in the registry")

    old_source = (
        approved.read_text(encoding="utf-8").splitlines(keepends=True)
        if approved is not None
        else []
    )
    new_source = current.read_text(encoding="utf-8").splitlines(keepends=True)
    diff = "".join(
        difflib.unified_diff(
            old_source,
            new_source,
            fromfile=f"approved/{approved.name}" if approved else "/dev/null",
            tofile=f"current/{current.name}",
        )
    )
    if print_diff:
        print(
            f"Approved hash: {sha256_file(approved) if approved else '(no prior approved source)'}"
        )
        print(f"Current hash:  {sha256_file(current)}")
        print("\nCode diff:")
        print(diff or "(no code differences)")

    attempt_results = []
    failures = []
    accepted_attempts, dry_run_reports = accepted_attempt_records()
    for challenge_id, start_path, artifacts in saved_attempts(spec):
        start = load_start(start_path)
        mode = str(start.get("mode", "unknown"))
        attempt_id = str(start.get("attempt_id", start_path.parent.name))
        label = f"{mode} attempt {attempt_id}"
        old = run_solver(approved, start_path, artifacts) if approved else None
        current_result = run_solver(current, start_path, artifacts)
        old_ok, old_error = (
            (False, old.get("error"))
            if old is not None and not old.get("ok")
            else check_answers(start, old)
            if old is not None
            else (False, "no prior approved source")
        )
        new_ok, new_error = (
            (False, current_result.get("error"))
            if not current_result.get("ok")
            else check_answers(start, current_result)
        )
        same_answers = bool(
            approved is not None
            and old_ok
            and new_ok
            and old is not None
            and old.get("answers") == current_result.get("answers")
        )
        accepted_answers = accepted_answers_for_attempt(
            start,
            attempt_id,
            accepted_attempts,
            dry_run_reports,
        )
        was_accepted = attempt_id in accepted_attempts
        if was_accepted and accepted_answers is None:
            failures.append(
                f"{label}: Game Master accepted this attempt, but its saved dry-run answer record is missing"
            )
        if (
            was_accepted
            and new_ok
            and accepted_answers is not None
            and accepted_answers != public_answers(
                start, current_result.get("answers", {})
            )
        ):
                failures.append(
                    f"{label}: current answers differ from the answer recorded for the accepted attempt"
                )
        if not new_ok:
            failures.append(f"{label}: current solver failed format/ID checks: {new_error}")
        unchanged_mode = mode in {"single_solve", "time_trial"}

        row = {
            "challenge": challenge_id,
            "attempt_id": attempt_id,
            "mode": mode,
            "artifact_count": len(artifacts),
            "accepted_by_game_master": was_accepted,
            "accepted_answers": accepted_answers,
            "approved_solver": {
                "valid": old_ok if approved is not None else None,
                "error": old_error,
            },
            "current_solver": {
                "valid": new_ok,
                "error": new_error,
                "answers": public_answers(start, current_result.get("answers", {}))
                if current_result.get("ok")
                else {},
            },
            "same_as_approved": (
                same_answers if approved is not None and old_ok and new_ok else None
            ),
        }
        attempt_results.append(row)
        if print_diff:
            print(f"\n{mode} — {attempt_id} ({len(artifacts)} artifact(s))")
            if accepted_answers is not None:
                print(f"  Game Master accepted: {accepted_answers}")
            elif was_accepted:
                print("  Game Master accepted: yes; saved answer record unavailable")
            else:
                print("  Game Master accepted: no accepted submission recorded for this attempt")
            if approved is None:
                print("  Approved solver: no prior source snapshot")
            elif old_ok and old is not None:
                print(f"  Approved solver: valid; answers {public_answers(start, old['answers'])}")
            else:
                print(f"  Approved solver: unable to solve ({old_error})")
            if new_ok:
                print(f"  Changed solver:  valid; answers {public_answers(start, current_result['answers'])}")
            else:
                print(f"  Changed solver:  FAILED ({new_error})")
            if approved is not None and unchanged_mode and old_ok and new_ok:
                print(f"  Comparison: {'unchanged' if same_answers else 'DIFFERENT'}")

    if not attempt_results:
        failures.append("No saved artifact attempts were found for offline review")
    report = {
        "solver": name,
        "approved_sha256": sha256_file(approved) if approved is not None else None,
        "current_sha256": sha256_file(current),
        "approved_source": str(approved.relative_to(ROOT)) if approved else None,
        "current_source": str(current.relative_to(ROOT)),
        "diff": diff,
        "attempts": attempt_results,
        "passed": not failures,
        "failures": failures,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "submission_count": 0,
        "network_requests": 0,
    }
    report_path = RUNS_DIR / f"{timestamp()}-{name}-offline-review.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"\nOffline review: {'PASSED' if report['passed'] else 'FAILED'}")
    if failures:
        for failure in failures:
            print(f"- {failure}")
    print(f"Report: {report_path.relative_to(ROOT)}")
    print("No Game Master requests or submissions were made.")
    return report_path


def approve_solver(name: str, report_path: pathlib.Path | None = None) -> None:
    registry = load_registry()
    spec = find_solver(registry, name)
    current = ROOT / str(spec.get("path", ""))
    if not current.is_file():
        raise ReviewError("Current solver source is missing")
    current_hash = sha256_file(current)

    if report_path is None:
        reports = sorted(
            RUNS_DIR.glob(f"*-{name}-offline-review.json"),
            key=lambda path: path.stat().st_mtime,
        )
        if not reports:
            raise ReviewError("No offline review report exists for this solver")
        report_path = reports[-1]
    else:
        report_path = report_path.resolve()
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewError("Cannot read the selected offline review report") from exc
    if (
        report.get("solver") != name
        or report.get("passed") is not True
        or report.get("current_sha256") != current_hash
    ):
        raise ReviewError("Latest offline review did not pass for the current source hash")

    assert_no_active_saved_timers(spec)

    snapshot = AGENT_DIR / "approved_solvers" / f"{name}-{current_hash}.py"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(current, snapshot)
    spec["approved_solver_sha256"] = current_hash
    spec["approved_source"] = str(snapshot.relative_to(ROOT))
    REGISTRY_PATH.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    attempts_reviewed = [
        {
            "attempt_id": item.get("attempt_id"),
            "mode": item.get("mode"),
            "current_solver_valid": (
                item.get("current_solver", {}).get("valid") is True
                if isinstance(item.get("current_solver"), dict)
                else False
            ),
        }
        for item in report.get("attempts", [])
        if isinstance(item, dict)
    ]
    approval_log = RUNS_DIR / f"{timestamp()}-self-approvals.jsonl"
    approval_event = {
        "time": dt.datetime.now(dt.timezone.utc).isoformat(),
        "action": "self_approval",
        "approval_type": "solver_hash",
        "solver": name,
        "solver_sha256": current_hash,
        "review_passed": True,
        "review_report": str(report_path.relative_to(ROOT)),
        "review_report_sha256": sha256_file(report_path),
        "attempts_reviewed": attempts_reviewed,
        "submission_count": 0,
        "network_requests": 0,
    }
    with approval_log.open("a", encoding="utf-8") as output:
        output.write(
            json.dumps(approval_event, ensure_ascii=False, sort_keys=True) + "\n"
        )
    print(f"Approved {name} at hash {current_hash}.")
    print(f"Snapshot: {snapshot.relative_to(ROOT)}")
    print(f"Self-approval log: {approval_log.relative_to(ROOT)}")
    print("Approval was recorded with no active saved timer and no Game Master request.")


def assert_no_active_saved_timers(
    spec: dict[str, Any],
    *,
    now: dt.datetime | None = None,
) -> None:
    current_time = now or dt.datetime.now(dt.timezone.utc)
    for _, start_path, _ in saved_attempts(spec):
        start = load_start(start_path)
        deadline = start.get("deadline")
        if isinstance(deadline, str):
            try:
                parsed = dt.datetime.fromisoformat(deadline.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ReviewError(f"Cannot verify saved timer deadline in {start_path}") from exc
            if parsed > current_time:
                raise ReviewError(
                    f"Cannot approve while a saved attempt timer is running: {start_path.parent.name}"
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    review_parser = subparsers.add_parser("review", help="diff and dry-run against saved attempts")
    review_parser.add_argument("solver")
    approve_parser = subparsers.add_parser("approve", help="record a reviewed source hash")
    approve_parser.add_argument("solver")
    approve_parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.action == "review":
            review_solver(args.solver)
        else:
            approve_solver(args.solver, args.report)
    except (ReviewError, subprocess.TimeoutExpired) as exc:
        print(f"solver_review stopped: {exc}", file=sys.stderr)
        return 2
    return 0


def print_offline_review(name: str) -> pathlib.Path:
    return review_solver(name)


if __name__ == "__main__":
    raise SystemExit(main())
