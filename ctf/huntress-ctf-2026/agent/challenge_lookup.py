#!/usr/bin/env python3
"""Resolve a displayed challenge name or ID through the documented list operation."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from agent.ctf_agent import base_challenge_id, challenge_entries
from agent.gm_client import GMClient


def normalize(value: str) -> str:
    return " ".join(value.casefold().split())


def challenge_families(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        challenge_id = str(entry["id"])
        grouped.setdefault(base_challenge_id(challenge_id), []).append(entry)

    families = []
    for base_id, modes in grouped.items():
        base_entry = next(
            (entry for entry in modes if str(entry["id"]) == base_id),
            modes[0],
        )
        families.append(
            {
                "id": base_id,
                "name": str(base_entry.get("name") or base_id),
                "day": base_entry.get("day"),
                "lane": base_entry.get("lane"),
            }
        )
    return sorted(
        families,
        key=lambda item: (normalize(str(item["name"])), str(item["id"])),
    )


def resolve(query: str, entries: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Return ('resolved'|'ambiguous'|'none', candidate challenge families)."""
    families = challenge_families(entries)
    normalized_query = normalize(query)
    id_candidates = [
        family
        for family in families
        if normalized_query in {
            normalize(str(family["id"])),
            normalize(str(family["id"]) + "/time_trial"),
            normalize(str(family["id"]) + "/mastery"),
        }
    ]
    if id_candidates:
        return "resolved", id_candidates

    exact = [
        family
        for family in families
        if normalize(str(family["name"])) == normalized_query
    ]
    if len(exact) == 1:
        return "resolved", exact
    if len(exact) > 1:
        return "ambiguous", exact

    suggestions = [
        family
        for family in families
        if normalized_query in normalize(str(family["name"]))
        or normalize(str(family["name"])) in normalized_query
    ]
    return "none", suggestions or families


def print_candidates(candidates: list[dict[str, Any]]) -> None:
    if not candidates:
        print("- No challenges were returned by the supported list operation.")
        return
    for candidate in candidates:
        detail = []
        if candidate.get("day") is not None:
            detail.append(f"day {candidate['day']}")
        if candidate.get("lane"):
            detail.append(str(candidate["lane"]))
        suffix = f" ({', '.join(detail)})" if detail else ""
        print(f"- {candidate['name']} — {candidate['id']}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve one challenge name or ID from the supported Game Master list."
    )
    parser.add_argument("query", help="display name or challenge ID")
    args = parser.parse_args()

    try:
        listing = GMClient().list_challenges(all_released=True)
        entries = challenge_entries(listing)
    except Exception as exc:
        print(f"Challenge lookup failed safely: {type(exc).__name__}", file=sys.stderr)
        return 2

    outcome, candidates = resolve(args.query, entries)
    if outcome == "resolved":
        candidate = candidates[0]
        print(f"Resolved challenge: {candidate['name']} ({candidate['id']})")
        return 0

    if outcome == "ambiguous":
        print(f"More than one challenge is named {args.query!r}:")
    else:
        print(f"No exact challenge name or ID matched {args.query!r}.")
        print("Possible candidates:")
    print_candidates(candidates)
    print("Choose one exact name or ID. No challenge was started.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
