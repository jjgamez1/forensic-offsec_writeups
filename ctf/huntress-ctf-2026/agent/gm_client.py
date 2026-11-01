#!/usr/bin/env python3
"""The Huntress CTF agent's sole Game Master proxy client."""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from agent.answer_ids import parse_answer_id


PROXY = "http://10.0.0.219/huntress-ctf-proxy"
ROOT = pathlib.Path(__file__).resolve().parent
FLAGS_PATH = ROOT / "private" / "flags.json"
REQUEST_LOG_PATH = ROOT / "runs" / "gm-client-events.jsonl"
MAX_TIMEOUT_RETRIES = 3
RETRY_WAIT_SECONDS = 0.5


class SubmissionStatusUnknown(RuntimeError):
    """A submit timed out and status could not confirm its outcome."""


def delivery_indexes(start: dict[str, Any]) -> list[int]:
    """Return zero-based artifact delivery indices referenced by start questions."""
    references: set[int] = set()
    for question in start.get("questions", []):
        description = str(question.get("artifact", ""))
        for match in re.finditer(r"\bdelivery\s+(\d+)\b", description, re.IGNORECASE):
            references.add(max(0, int(match.group(1)) - 1))
    return sorted(references)


class GMClient:
    """Client for operations documented by the Homebase Game Master interface."""

    def __init__(
        self,
        *,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        sleep_func: Callable[[float], None] = time.sleep,
        retry_wait_seconds: float = RETRY_WAIT_SECONDS,
    ) -> None:
        self.proxy = PROXY
        self.event_sink = event_sink or self._default_event_sink
        self.sleep_func = sleep_func
        self.retry_wait_seconds = retry_wait_seconds

    @staticmethod
    def _default_event_sink(event: dict[str, Any]) -> None:
        REQUEST_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with REQUEST_LOG_PATH.open("a", encoding="utf-8") as output:
            output.write(
                json.dumps(
                    {"time": dt.datetime.now(dt.timezone.utc).isoformat(), **event},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )

    def _log(self, event: dict[str, Any]) -> None:
        self.event_sink(event)

    @staticmethod
    def _is_timeout(exc: BaseException) -> bool:
        if isinstance(exc, (TimeoutError, socket.timeout)):
            return True
        return (
            isinstance(exc, urllib.error.URLError)
            and isinstance(exc.reason, (TimeoutError, socket.timeout))
        )

    @staticmethod
    def _read_response(response: Any) -> bytes:
        return response.read()

    def _request_bytes(
        self,
        url: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: float = 12,
        operation: str = "request",
        challenge: str | None = None,
        retry_timeouts: bool = True,
    ) -> bytes:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {} if data is None else {"Content-Type": "application/json"}
        request = urllib.request.Request(url, data=data, headers=headers)
        retries = MAX_TIMEOUT_RETRIES if retry_timeouts else 0
        for attempt in range(1, retries + 2):
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    return self._read_response(response)
            except (TimeoutError, socket.timeout, urllib.error.URLError) as exc:
                if not self._is_timeout(exc):
                    raise
                will_retry = attempt <= retries
                self._log(
                    {
                        "action": "gm_request_timeout",
                        "operation": operation,
                        "challenge": challenge,
                        "attempt": attempt,
                        "will_retry": will_retry,
                    }
                )
                if not will_retry:
                    raise
                next_attempt = attempt + 1
                self._log(
                    {
                        "action": "gm_request_resend",
                        "operation": operation,
                        "challenge": challenge,
                        "attempt": next_attempt,
                    }
                )
                self.sleep_func(self.retry_wait_seconds)
        raise AssertionError("request retry loop exited without a response or exception")

    def _request_json(
        self,
        url: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: float = 12,
        operation: str = "request",
        challenge: str | None = None,
        retry_timeouts: bool = True,
    ) -> dict[str, Any]:
        raw = self._request_bytes(
            url,
            payload,
            timeout=timeout,
            operation=operation,
            challenge=challenge,
            retry_timeouts=retry_timeouts,
        )
        try:
            result = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("Game Master returned a non-JSON response") from exc
        if not isinstance(result, dict):
            raise RuntimeError("Game Master returned an unexpected JSON response")
        return result

    @staticmethod
    def _read_private_flags() -> dict[str, str]:
        try:
            contents = json.loads(FLAGS_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError("Could not read the private flags file") from exc
        if not isinstance(contents, dict):
            raise RuntimeError("The private flags file must contain a JSON object")
        return {str(key): str(value) for key, value in contents.items()}

    @classmethod
    def _save_flag(cls, challenge: str, flag: Any) -> None:
        if not isinstance(flag, str) or not flag:
            return
        FLAGS_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(FLAGS_PATH.parent, 0o700)
        flags = cls._read_private_flags()
        flags[challenge] = flag
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".flags-", dir=FLAGS_PATH.parent
        )
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as output:
                json.dump(flags, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_name, FLAGS_PATH)
            os.chmod(FLAGS_PATH, 0o600)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

    def store_private_flag(self, label: str, flag: str) -> None:
        """Persist a flag received from the assigned target without printing it."""
        self._save_flag(label, flag)

    @staticmethod
    def _without_flags(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: GMClient._without_flags(item)
                for key, item in value.items()
                if str(key).casefold() != "flag"
            }
        if isinstance(value, list):
            return [GMClient._without_flags(item) for item in value]
        return value

    def _secure_json(
        self, challenge: str, result: dict[str, Any]
    ) -> dict[str, Any]:
        self._save_flag(challenge, result.get("flag"))
        return self._without_flags(result)

    def list_challenges(self, all_released: bool = False) -> dict[str, Any]:
        """List offered challenges, privately saving and redacting returned flags.

        The all_released option is used only because the live list response
        advertises op=list&all=true as a supported way to see released days.
        """
        parameters = {"op": "list"}
        if all_released:
            parameters["all"] = "true"
        query = urllib.parse.urlencode(parameters)
        result = self._request_json(
            self.proxy + "?" + query,
            timeout=30,
            operation="list",
        )
        challenges = result.get("challenges")
        if not isinstance(challenges, list):
            raise RuntimeError("Game Master list response did not contain a challenge list")

        for challenge in challenges:
            if isinstance(challenge, dict) and isinstance(challenge.get("id"), str):
                self._save_flag(challenge["id"], challenge.get("flag"))
        return self._without_flags(result)

    def start(
        self, challenge: str, *, run_for_time: bool | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"challenge": challenge}
        if run_for_time is not None:
            payload["run_for_time"] = run_for_time
        result = self._request_json(
            self.proxy,
            payload,
            operation="start",
            challenge=challenge,
        )
        return self._secure_json(challenge, result)

    def status(self, challenge: str) -> dict[str, Any]:
        query = urllib.parse.urlencode(
            {"op": "status", "challenge": challenge}
        )
        result = self._request_json(
            self.proxy + "?" + query,
            operation="status",
            challenge=challenge,
        )
        return self._secure_json(challenge, result)

    def retry(
        self, challenge: str, *, run_for_time: bool | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"op": "retry", "challenge": challenge}
        if run_for_time is not None:
            payload["run_for_time"] = run_for_time
        result = self._request_json(
            self.proxy,
            payload,
            operation="retry",
            challenge=challenge,
            retry_timeouts=False,
        )
        return self._secure_json(challenge, result)

    def practice(self, challenge: str) -> dict[str, Any]:
        """Continue the same expired attempt untimed after fresh variants are exhausted."""
        result = self._request_json(
            self.proxy,
            {"op": "practice", "challenge": challenge},
            operation="practice",
            challenge=challenge,
        )
        return self._secure_json(challenge, result)

    def start_or_retry_expired(
        self,
        challenge: str,
        timed: bool,
        *,
        run_for_time: bool | None = None,
    ) -> dict[str, Any]:
        """Resume a timed attempt, retrying only when status reports an expired deadline."""
        if not timed:
            return self.start(challenge)

        try:
            current = self.status(challenge)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                current = {}
            elif exc.code == 409:
                try:
                    body = json.loads(exc.read())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise exc
                if not isinstance(body, dict) or body.get("error") != "start_required":
                    raise exc
                current = {}
            else:
                raise

        deadline = current.get("deadline")
        expired = (
            isinstance(current.get("result"), str)
            and current["result"].casefold() == "expired"
        )
        if expired:
            if current.get("unique_attempts_remaining") == 0:
                if current.get("next_op") == "practice":
                    return self.practice(challenge)
                raise RuntimeError(
                    "No fresh timed variants remain and the Game Master did not offer practice"
                )
            return self.retry(challenge, run_for_time=run_for_time)
        if isinstance(deadline, str) and deadline:
            try:
                expires = dt.datetime.fromisoformat(
                    deadline.replace("Z", "+00:00")
                ).timestamp()
            except ValueError as exc:
                raise RuntimeError("Game Master returned an invalid deadline") from exc
            now = dt.datetime.now(dt.timezone.utc).timestamp()
            if expires <= now:
                if current.get("unique_attempts_remaining") == 0:
                    if current.get("next_op") == "practice":
                        return self.practice(challenge)
                    raise RuntimeError(
                        "No fresh timed variants remain and the Game Master did not offer practice"
                    )
                return self.retry(challenge, run_for_time=run_for_time)
        return self.start(challenge, run_for_time=run_for_time)

    def artifact(self, challenge: str, delivery: int | None = None) -> bytes:
        parameters: dict[str, str | int] = {
            "op": "artifact",
            "challenge": challenge,
        }
        if delivery is not None:
            parameters["delivery"] = delivery
        query = urllib.parse.urlencode(parameters)
        return self._request_bytes(
            self.proxy + "?" + query,
            operation="artifact",
            challenge=challenge,
        )

    @staticmethod
    def _submission_result_from_status(status: dict[str, Any]) -> str | None:
        accepted_results = {"correct", "accepted", "incorrect"}
        for key in ("result", "submission_result", "last_result", "last_submission_result"):
            value = status.get(key)
            if isinstance(value, str) and value.casefold() in accepted_results:
                return "CORRECT" if value.casefold() == "correct" else value.casefold()
        if status.get("solved") is True or status.get("complete") is True:
            return "CORRECT"
        for key in ("last_submission", "submission"):
            nested = status.get(key)
            if isinstance(nested, dict):
                result = GMClient._submission_result_from_status(nested)
                if result:
                    return result
        return None

    def submit(
        self, challenge: str, answers: dict[str, str]
    ) -> dict[str, Any]:
        try:
            result = self._request_json(
                self.proxy,
                {"challenge": challenge, "answers": answers},
                operation="submit",
                challenge=challenge,
                retry_timeouts=False,
            )
        except (TimeoutError, socket.timeout, urllib.error.URLError) as exc:
            if not self._is_timeout(exc):
                raise
            self._log(
                {
                    "action": "gm_submit_status_check_started",
                    "challenge": challenge,
                }
            )
            try:
                status = self.status(challenge)
            except Exception as status_exc:
                self._log(
                    {
                        "action": "gm_submit_status_check_failed",
                        "challenge": challenge,
                        "exception_type": type(status_exc).__name__,
                    }
                )
                raise SubmissionStatusUnknown(
                    "submit timed out and the attempt status could not be checked"
                ) from status_exc
            confirmed = self._submission_result_from_status(status)
            self._log(
                {
                    "action": "gm_submit_status_checked",
                    "challenge": challenge,
                    "outcome": confirmed or "unknown",
                }
            )
            if confirmed is None:
                raise SubmissionStatusUnknown(
                    "submit timed out and the attempt status did not confirm its outcome"
                ) from exc
            result = dict(status)
            result["result"] = confirmed
        self._save_flag(challenge, result.get("flag"))
        return self._without_flags(result)
