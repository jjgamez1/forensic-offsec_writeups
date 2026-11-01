from __future__ import annotations

import base64
import codecs
import io
import pathlib
import tempfile
import unittest
import zipfile

from agent.solvers.hex_last_line import solve_detailed


def hex_text(value: str) -> bytes:
    return value.encode("utf-8").hex().encode("ascii")


def numbered_text(slug: str) -> bytes:
    stage1 = base64.b64encode(b"Decoded instruction: ").decode().rstrip("=")
    stage2 = codecs.encode("submit this exact answer to the Game Master: ", "rot_13")
    stage3 = f"{slug}\n".encode("utf-8").hex()
    return (
        f"01\t{stage1}\n02\t{stage2}\n03\t{stage3}\n"
    ).encode("utf-8")


class HexLastLineTests(unittest.TestCase):
    def test_multiple_sets_select_different_members_by_question_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_path = pathlib.Path(temporary) / "bundle.zip"
            container = io.BytesIO()
            with zipfile.ZipFile(container, "w") as archive:
                archive.writestr(
                    "delivery-a/alpha.txt",
                    hex_text("decoy line\namber-river-lantern-12\n"),
                )
                archive.writestr(
                    "delivery-b/beta.txt",
                    numbered_text("cobalt-forest-window-34"),
                )
            artifact_path.write_bytes(container.getvalue())

            start = {
                "answer_ids": ["set1.message", "set2.message"],
                "questions": [
                    {
                        "id": "set1.message",
                        "artifact": "bundle.zip -> delivery-a/alpha.txt",
                        "answer_format": {
                            "kind": "pattern",
                            "syntax": (
                                "three lowercase words separated by hyphens, "
                                "followed by a hyphen and a two-digit number"
                            ),
                        },
                    },
                    {
                        "id": "set2.message",
                        "artifact": "bundle.zip -> delivery-b/beta.txt",
                        "answer_format": {
                            "kind": "pattern",
                            "syntax": (
                                "three lowercase words separated by hyphens, "
                                "followed by a hyphen and a two-digit number"
                            ),
                        },
                    },
                ],
            }

            answers, reasoning, replay = solve_detailed(start, [artifact_path])

        self.assertFalse(replay)
        self.assertEqual(
            answers,
            {
                "set1.message": "amber-river-lantern-12",
                "set2.message": "cobalt-forest-window-34",
            },
        )
        self.assertEqual(set(reasoning), set(start["answer_ids"]))


if __name__ == "__main__":
    unittest.main()
