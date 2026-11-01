from __future__ import annotations

import unittest

from agent.solvers.common import validate_answer_format
from agent.solvers.rail_fence_warmup import _decode, _decode_stage


def counted_comma_encode(text: str) -> bytes:
    runs: list[str] = []
    index = 0
    while index < len(text):
        end = index + 1
        while end < len(text) and text[end] == text[index]:
            end += 1
        runs.append(f"{end - index}:{text[index]}")
        index = end
    return (",".join(runs) + ",").encode("utf-8")


def rail_fence_encode(text: str, rails: int) -> bytes:
    rows: list[list[str]] = [[] for _ in range(rails)]
    row = 0
    direction = 1
    for char in text:
        rows[row].append(char)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    return "".join("".join(part) for part in rows).encode("utf-8")


class WarmupInstructionTests(unittest.TestCase):
    question = {
        "question": (
            "Decode the assigned blob completely. What exact answer slug does its "
            "final non-empty decoded line instruct you to submit?"
        ),
        "answer_format": {
            "kind": "pattern",
            "syntax": (
                "three lowercase words separated by hyphens, followed by a hyphen "
                "and a two-digit number; submit the slug only"
            ),
        },
    }

    def test_preserves_explicit_instruction_suffix_after_slug(self) -> None:
        instructed_line = (
            "Nice work decoding this warmup! To solve, submit this exact answer "
            "to the Game Master: brisk-sparrow-wizard-23-6761"
        )
        answer, _ = _decode(rail_fence_encode(instructed_line, 3), "blob-34.txt")

        self.assertEqual(answer, "brisk-sparrow-wizard-23-6761")
        validate_answer_format("set34.message", answer, self.question)

    def test_returns_plain_slug_when_instruction_has_no_extra_text(self) -> None:
        instructed_line = (
            "Nice work decoding this warmup! To solve, submit this exact answer "
            "to the Game Master: brisk-sparrow-wizard-23"
        )
        answer, _ = _decode(rail_fence_encode(instructed_line, 3), "blob-01.txt")

        self.assertEqual(answer, "brisk-sparrow-wizard-23")
        validate_answer_format("set1.message", answer, self.question)

    def test_decodes_counted_comma_runs_and_keeps_comma_character(self) -> None:
        instructed_line = (
            "Nice work decoding this warmup! To solve, submit this exact answer "
            "to the Game Master: jaunty-compass-mosaic-76"
        )
        answer, reasoning = _decode(
            counted_comma_encode(instructed_line), "blob.txt"
        )

        self.assertEqual(answer, "jaunty-compass-mosaic-76")
        self.assertIn("count:character runs", reasoning)
        validate_answer_format("message", answer, self.question)

    def test_decodes_counted_comma_suffix_as_numbered_stage_24(self) -> None:
        self.assertEqual(
            _decode_stage(24, "1:a,1:l,1:-,1:9,1:8,", "blob-01.txt"),
            "al-98",
        )


if __name__ == "__main__":
    unittest.main()
