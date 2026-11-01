"""Pure parsing helpers for the Game Master answer field identifiers."""

from __future__ import annotations

import re


def parse_answer_id(answer_id: str) -> tuple[str | None, str]:
    """Split plain, set-scoped, and slot-scoped answer IDs into scope and field."""
    nested = re.match(r"^(set\d+)\.(slot\d+)_(.+)$", answer_id)
    if nested:
        return f"{nested.group(1)}.{nested.group(2)}", nested.group(3)

    match = re.match(r"^(set\d+)\.(.+)$", answer_id)
    if not match:
        match = re.match(r"^(slot\d+)_(.+)$", answer_id)
    if match:
        return match.group(1), match.group(2)
    return None, answer_id
