from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import ctf_agent
from agent import challenge_lookup
from agent import replay_day1
from agent import solver_review
from agent.ctf_agent import (
    SubmissionLimitReached,
    SubmissionPolicyError,
    check_submission_policy,
    display_answers,
    log_event,
    register_private_value,
    solver_hash_review_required,
    timed_auto_submit_allowed,
    validate_answers,
    first_incomplete,
    write_challenge_note,
)


class SafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        ctf_agent.PRIVATE_VALUES.clear()

    def tearDown(self) -> None:
        ctf_agent.PRIVATE_VALUES.clear()

    def test_three_submission_limit(self) -> None:
        state = {
            "submissions": {
                "challenge/time_trial": {
                    "count": 3,
                    "last_result": "incorrect",
                }
            }
        }
        with self.assertRaises(SubmissionLimitReached):
            check_submission_policy(
                state,
                "challenge/time_trial",
                "attempt-4",
                "answer-hash",
                "solver-hash",
                "diagnosis explains the correction",
            )

    def test_first_incomplete_respects_day_floor(self) -> None:
        entries = [
            {"id": "day-01", "day": 1, "solved": False},
            {"id": "day-02", "day": 2, "solved": False},
        ]
        with patch.object(ctf_agent, "already_handed_back", return_value=False):
            self.assertEqual(
                first_incomplete(entries, {"handed_back": []}, min_day=2),
                "day-02",
            )

    def test_resubmission_requires_diagnosis(self) -> None:
        state = {
            "submissions": {
                "challenge": {
                    "count": 1,
                    "last_result": "incorrect",
                    "answer_hash": "old-answer",
                    "solver_hash": "old-solver",
                }
            }
        }
        with self.assertRaises(SubmissionPolicyError):
            check_submission_policy(
                state,
                "challenge",
                "attempt-2",
                "new-answer",
                "new-solver",
                None,
            )

    def test_changed_solver_hash_requires_offline_review_before_timed_start(self) -> None:
        approved = {
            "approved_solver_sha256": "approved-code-hash",
        }
        self.assertTrue(
            solver_hash_review_required(approved, "changed-code-hash")
        )
        self.assertFalse(
            timed_auto_submit_allowed(approved, "changed-code-hash")
        )
        self.assertFalse(
            solver_hash_review_required(approved, "approved-code-hash")
        )
        self.assertTrue(
            timed_auto_submit_allowed(approved, "approved-code-hash")
        )

    def test_challenge_name_lookup_requires_one_exact_family(self) -> None:
        entries = [
            {"id": "warmups-day-02", "name": "Half a Turn", "day": 2},
            {"id": "warmups-day-02/time_trial", "name": "Half a Turn", "day": 2},
            {"id": "warmups-day-02/mastery", "name": "Half a Turn", "day": 2},
            {"id": "warmups-day-03", "name": "Half a Turn", "day": 3},
            {"id": "warmups-day-04", "name": "A Different Challenge", "day": 4},
        ]
        outcome, candidates = challenge_lookup.resolve(" Half a Turn ", entries)
        self.assertEqual(outcome, "ambiguous")
        self.assertEqual(
            [candidate["id"] for candidate in candidates],
            ["warmups-day-02", "warmups-day-03"],
        )

        outcome, candidates = challenge_lookup.resolve(
            "warmups-day-02/time_trial", entries
        )
        self.assertEqual(outcome, "resolved")
        self.assertEqual(candidates[0]["id"], "warmups-day-02")

        outcome, candidates = challenge_lookup.resolve("half", entries)
        self.assertEqual(outcome, "none")
        self.assertEqual(
            [candidate["id"] for candidate in candidates],
            ["warmups-day-02", "warmups-day-03"],
        )

    def test_solver_hash_cannot_be_approved_while_saved_timer_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            challenge_dir = Path(temporary) / "warmups-day-02"
            attempt_dir = challenge_dir / "active-attempt"
            attempt_dir.mkdir(parents=True)
            start_path = attempt_dir / "start.json"
            start_path.write_text(
                json.dumps(
                    {
                        "attempt_id": "active-attempt",
                        "mode": "mastery",
                        "deadline": "2026-10-19T00:30:00Z",
                    }
                ),
                encoding="utf-8",
            )
            (attempt_dir / "artifact-00.bin").write_bytes(b"saved")
            with patch.object(solver_review, "ARTIFACTS_DIR", Path(temporary)):
                with self.assertRaises(solver_review.ReviewError):
                    solver_review.assert_no_active_saved_timers(
                        {"challenge_ids": ["warmups-day-02"]},
                        now=dt.datetime(2026, 10, 19, 0, 20, tzinfo=dt.timezone.utc),
                    )

    def test_answer_ids_must_match_exactly(self) -> None:
        start = {
            "answer_ids": ["message"],
            "questions": [{"id": "message", "answer_format": {"kind": "text"}}],
        }
        with self.assertRaises(ctf_agent.AgentError):
            validate_answers(
                start,
                {"unexpected": "value"},
                {"unexpected": "reason"},
            )

    def test_flag_sentinel_never_reaches_console_notes_or_run_log(self) -> None:
        sentinel = "FLAG_SENTINEL_DO_NOT_DISCLOSE_7f2ac91d"
        register_private_value(sentinel)

        question = {
            "id": "flag",
            "question": "Submit the flag",
            "answer_format": {"kind": "text"},
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            display_answers(
                {"flag": sentinel},
                {"flag": sentinel},
                {question["id"]: question},
            )
        self.assertNotIn(sentinel, output.getvalue())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log_path = root / "run.jsonl"
            note_dir = root / "notes"
            with patch.object(ctf_agent, "NOTES_DIR", note_dir):
                write_challenge_note(
                    "test-challenge",
                    {
                        "name": sentinel,
                        "lane": "test",
                        "prompt": f"Prompt containing {sentinel}",
                    },
                    [{"mode": "single_solve", "result": "CORRECT", "submissions": 1}],
                    [],
                    "test_solver",
                )
            log_event(
                log_path,
                {
                    "action": "test",
                    "flag": sentinel,
                    "context": f"Contains {sentinel}",
                },
            )
            public_outputs = (
                (note_dir / "test-challenge.md").read_text(encoding="utf-8")
                + log_path.read_text(encoding="utf-8")
            )
            self.assertNotIn(sentinel, public_outputs)

    def test_offline_replay_has_no_submission_client(self) -> None:
        source = Path(replay_day1.__file__).read_text(encoding="utf-8")
        self.assertNotIn("GMClient", source)
        self.assertNotIn(".submit(", source)
        self.assertFalse(hasattr(replay_day1, "GMClient"))
        check = subprocess.run(
            [
                sys.executable,
                "-c",
                "import agent.replay_day1, sys; "
                "raise SystemExit('network client imported' "
                "if 'agent.gm_client' in sys.modules else 0)",
            ],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(check.returncode, 0, check.stderr)


if __name__ == "__main__":
    unittest.main()
