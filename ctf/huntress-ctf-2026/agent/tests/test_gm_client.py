from __future__ import annotations

import json
import socket
import unittest
from unittest.mock import patch

from agent.gm_client import GMClient, SubmissionStatusUnknown


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def json_response(value: dict[str, object]) -> FakeResponse:
    return FakeResponse(json.dumps(value).encode("utf-8"))


class GMClientRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events: list[dict[str, object]] = []
        self.waits: list[float] = []
        self.client = GMClient(
            event_sink=self.events.append,
            sleep_func=self.waits.append,
            retry_wait_seconds=0.25,
        )
        self.client.proxy = "http://game-master.test/proxy"

    def test_list_status_artifact_and_start_retry_timeouts(self) -> None:
        cases = (
            (
                "list",
                lambda: self.client.list_challenges(),
                json_response({"challenges": []}),
            ),
            (
                "status",
                lambda: self.client.status("sample"),
                json_response({"deadline": None}),
            ),
            (
                "artifact",
                lambda: self.client.artifact("sample"),
                FakeResponse(b"artifact"),
            ),
            (
                "start",
                lambda: self.client.start("sample"),
                json_response({"attempt_id": "attempt-1"}),
            ),
        )
        for operation, call, success in cases:
            with self.subTest(operation=operation):
                self.events.clear()
                self.waits.clear()
                with patch(
                    "agent.gm_client.urllib.request.urlopen",
                    side_effect=[socket.timeout("temporary"), success],
                ) as urlopen:
                    call()
                self.assertEqual(urlopen.call_count, 2)
                self.assertEqual(self.waits, [0.25])
                self.assertEqual(
                    [event["action"] for event in self.events],
                    ["gm_request_timeout", "gm_request_resend"],
                )
                self.assertEqual(self.events[0]["operation"], operation)
                self.assertTrue(self.events[0]["will_retry"])

    def test_safe_request_allows_three_retries_and_logs_each_resend(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=[
                socket.timeout("first"),
                socket.timeout("second"),
                socket.timeout("third"),
                json_response({"challenges": []}),
            ],
        ) as urlopen:
            self.client.list_challenges()

        self.assertEqual(urlopen.call_count, 4)
        self.assertEqual(self.waits, [0.25, 0.25, 0.25])
        self.assertEqual(
            sum(event["action"] == "gm_request_timeout" for event in self.events),
            3,
        )
        self.assertEqual(
            sum(event["action"] == "gm_request_resend" for event in self.events),
            3,
        )

    def test_final_timeout_is_logged_without_an_extra_resend(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=socket.timeout("persistent"),
        ) as urlopen:
            with self.assertRaises(socket.timeout):
                self.client.status("sample")

        self.assertEqual(urlopen.call_count, 4)
        self.assertFalse(self.events[-1]["will_retry"])
        self.assertEqual(
            sum(event["action"] == "gm_request_resend" for event in self.events),
            3,
        )

    def test_explicit_retry_operation_is_never_resent_after_timeout(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=socket.timeout("retry request timed out"),
        ) as urlopen:
            with self.assertRaises(socket.timeout):
                self.client.retry("sample")

        self.assertEqual(urlopen.call_count, 1)
        self.assertEqual(self.events[0]["operation"], "retry")
        self.assertFalse(self.events[0]["will_retry"])
        self.assertFalse(any(event["action"] == "gm_request_resend" for event in self.events))

    def test_expired_status_uses_retry_operation(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=[
                json_response({"result": "expired"}),
                json_response({"attempt_id": "attempt-2"}),
            ],
        ) as urlopen:
            result = self.client.start_or_retry_expired("sample", timed=True)

        self.assertEqual(result["attempt_id"], "attempt-2")
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(urlopen.call_args_list[0].args[0].get_method(), "GET")
        retry_request = urlopen.call_args_list[1].args[0]
        self.assertEqual(retry_request.get_method(), "POST")
        self.assertEqual(
            json.loads(retry_request.data),
            {"op": "retry", "challenge": "sample"},
        )

    def test_expired_status_with_no_fresh_variants_uses_practice(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=[
                json_response(
                    {
                        "result": "expired",
                        "unique_attempts_remaining": 0,
                        "next_op": "practice",
                    }
                ),
                json_response({"attempt_id": "same-attempt", "result": "active"}),
            ],
        ) as urlopen:
            result = self.client.start_or_retry_expired("sample", timed=True)

        self.assertEqual(result["attempt_id"], "same-attempt")
        self.assertEqual(urlopen.call_count, 2)
        practice_request = urlopen.call_args_list[1].args[0]
        self.assertEqual(
            json.loads(practice_request.data),
            {"op": "practice", "challenge": "sample"},
        )

    def test_expired_status_with_no_variants_does_not_call_retry_without_practice(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            return_value=json_response(
                {"result": "expired", "unique_attempts_remaining": 0}
            ),
        ) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "No fresh timed variants remain"):
                self.client.start_or_retry_expired("sample", timed=True)

        self.assertEqual(urlopen.call_count, 1)

    def test_submit_timeout_checks_status_and_never_resends_submit(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=[
                socket.timeout("submit timed out"),
                json_response({"solved": True}),
            ],
        ) as urlopen:
            result = self.client.submit("sample", {"answer": "value"})

        self.assertEqual(result["result"], "CORRECT")
        self.assertEqual(urlopen.call_count, 2)
        first_request = urlopen.call_args_list[0].args[0]
        second_request = urlopen.call_args_list[1].args[0]
        self.assertEqual(first_request.get_method(), "POST")
        self.assertEqual(second_request.get_method(), "GET")
        self.assertEqual(
            [event["action"] for event in self.events],
            [
                "gm_request_timeout",
                "gm_submit_status_check_started",
                "gm_submit_status_checked",
            ],
        )
        self.assertEqual(self.events[-1]["outcome"], "CORRECT")

    def test_submit_timeout_with_unclear_status_stays_unknown(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=[
                socket.timeout("submit timed out"),
                json_response({"deadline": "later"}),
            ],
        ) as urlopen:
            with self.assertRaises(SubmissionStatusUnknown):
                self.client.submit("sample", {"answer": "value"})

        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(
            [call.args[0].get_method() for call in urlopen.call_args_list],
            ["POST", "GET"],
        )
        self.assertEqual(self.events[-1]["outcome"], "unknown")

    def test_status_check_retries_after_submit_timeout(self) -> None:
        with patch(
            "agent.gm_client.urllib.request.urlopen",
            side_effect=[
                socket.timeout("submit timed out"),
                socket.timeout("status timed out once"),
                json_response({"last_submission": {"result": "accepted", "remaining": 1}}),
            ],
        ) as urlopen:
            result = self.client.submit("sample", {"answer": "value"})

        self.assertEqual(result["result"], "accepted")
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(
            [call.args[0].get_method() for call in urlopen.call_args_list],
            ["POST", "GET", "GET"],
        )
        self.assertIn(
            {"action": "gm_request_resend", "operation": "status", "challenge": "sample", "attempt": 2},
            self.events,
        )


if __name__ == "__main__":
    unittest.main()
