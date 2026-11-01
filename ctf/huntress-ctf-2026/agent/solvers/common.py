"""Shared offline input, answer mapping, and format checks for CTF solvers."""

from __future__ import annotations

import argparse
import io
import json
import pathlib
import re
import sys
import zipfile
from collections.abc import Callable, Iterable
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.runtime import reexec_in_configured_environment


class SolverError(RuntimeError):
    """A required answer could not be derived from the assigned bytes."""


def elf_machine_name(value: str) -> str:
    """Apply the shared short-name mapping used for ELF machine answers."""
    if "X86-64" in value.upper():
        return "x86-64"
    return value


def load_start(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SolverError(f"Cannot read start response JSON: {path}") from exc
    if not isinstance(value, dict):
        raise SolverError("Start response must be a JSON object")
    return value


def answer_ids_and_replay(
    start: dict[str, Any],
) -> tuple[list[str], bool]:
    provided = start.get("answer_ids")
    if isinstance(provided, list) and provided and all(
        isinstance(item, str) and item for item in provided
    ):
        ids = provided
        replay = False
    elif start.get("result") == "CORRECT":
        # Completed attempts omit answer_ids; for a no-submit replay, use the exact
        # field IDs returned with the completed response's player-facing questions.
        questions = start.get("questions")
        ids = [
            item["id"]
            for item in questions
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ] if isinstance(questions, list) else []
        replay = True
    else:
        raise SolverError("Start response has no answer_ids for an active attempt")

    if not ids or len(ids) != len(set(ids)):
        raise SolverError("Start response has no unique answer field IDs")
    return ids, replay


def questions_by_id(start: dict[str, Any], answer_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    questions = start.get("questions")
    if not isinstance(questions, list):
        raise SolverError("Start response has no questions array")
    by_id = {
        item["id"]: item
        for item in questions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    result = {}
    for answer_id in answer_ids:
        question = by_id.get(answer_id)
        if question is None:
            scope, field = parse_answer_id(answer_id)
            matches = []
            for question_id, candidate in by_id.items():
                question_scope, question_field = parse_answer_id(question_id)
                if question_field == field and (
                    question_scope == scope
                    or (question_scope is None and scope is None)
                ):
                    matches.append(candidate)
            if len(matches) != 1:
                raise SolverError(
                    f"Cannot map answer field {answer_id!r} to one returned question"
                )
            question = matches[0]
        result[answer_id] = question
    return result


def load_artifacts(paths: Iterable[pathlib.Path]) -> list[tuple[pathlib.Path, bytes]]:
    loaded = []
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SolverError(f"Cannot read assigned artifact: {path}") from exc
        loaded.append((path, data))
    if not loaded:
        raise SolverError("At least one assigned artifact path is required")
    return loaded


def iter_zip_files(
    data: bytes,
    label: str,
    *,
    encrypted_error: str = "Encrypted ZIP member requires an AES-capable reader",
    depth: int = 0,
):
    """Yield (container path, bytes) leaves, recursing by ZIP magic bytes."""
    if depth > 8:
        raise SolverError("Nested ZIP depth exceeds the safe inspection limit")
    if not data.startswith(b"PK\x03\x04"):
        yield label, data
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 1:
                    raise SolverError(encrypted_error)
                member_data = archive.read(info)
                member_label = f"{label}/{info.filename}"
                if member_data.startswith(b"PK\x03\x04"):
                    yield from iter_zip_files(
                        member_data,
                        member_label,
                        encrypted_error=encrypted_error,
                        depth=depth + 1,
                    )
                else:
                    yield member_label, member_data
    except zipfile.BadZipFile as exc:
        raise SolverError(f"Bytes identified as ZIP could not be parsed: {label}") from exc


def artifact_hint(question: dict[str, Any]) -> str:
    value = question.get("artifact")
    return value if isinstance(value, str) else ""


def hinted_member(question: dict[str, Any]) -> str | None:
    hint = artifact_hint(question)
    if "->" not in hint:
        return None
    return hint.rsplit("->", 1)[1].strip().replace("\\", "/")


def unique_by_hint(
    candidates: list[tuple[str, bytes]], hint: str, *, description: str
) -> tuple[str, bytes]:
    normalized = hint.replace("\\", "/").strip("/")
    matches = [
        item
        for item in candidates
        if item[0].replace("\\", "/").endswith("/" + normalized)
        or item[0].replace("\\", "/") == normalized
    ]
    if not matches and "/" not in normalized:
        matches = [
            item for item in candidates
            if pathlib.PurePosixPath(item[0]).name == normalized
        ]
    if len(matches) != 1:
        raise SolverError(
            f"Could not resolve {description} {hint!r} to exactly one assigned file "
            f"(found {len(matches)})"
        )
    return matches[0]


def validate_answer_format(
    answer_id: str, value: str, question: dict[str, Any]
) -> None:
    answer_format = question.get("answer_format")
    if not isinstance(answer_format, dict):
        raise SolverError(f"{answer_id}: returned question has no answer_format")
    kind = answer_format.get("kind")
    syntax = str(answer_format.get("syntax", ""))
    if kind == "exact_text":
        if not isinstance(value, str) or not value:
            raise SolverError(f"{answer_id}: expected non-empty exact text")
        return
    if kind == "enum":
        accepted = answer_format.get("accepted_values")
        if not isinstance(accepted, list) or value not in accepted:
            raise SolverError(f"{answer_id}: value is outside the returned enum")
        return
    if kind == "ordered_tokens":
        if not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(?:>[A-Za-z][A-Za-z0-9_]*)*", value
        ):
            raise SolverError(
                f"{answer_id}: value must be the exact ordered tokens joined by >"
            )
        return
    if kind == "integer":
        if not re.fullmatch(r"-?\d+", value):
            raise SolverError(f"{answer_id}: value is not a base-10 integer")
        return
    if kind == "mitre_attack_id":
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
            raise SolverError(f"{answer_id}: value is not a MITRE ATT&CK technique ID")
        return
    if kind == "json":
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise SolverError(f"{answer_id}: value is not valid JSON") from exc
        if "array" in syntax.lower() and not isinstance(decoded, list):
            raise SolverError(f"{answer_id}: value is not a JSON array")
        if "strings" in syntax.lower() and (
            not isinstance(decoded, list)
            or not all(isinstance(item, str) for item in decoded)
        ):
            raise SolverError(f"{answer_id}: expected a JSON array of strings")
        return
    if kind == "pattern":
        syntax_lower = syntax.lower()
        if "canonical guid" in syntax_lower:
            if re.fullmatch(
                r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}",
                value,
            ):
                return
            raise SolverError(f"{answer_id}: value is not canonical GUID text")
        if (
            "mitre attack" in syntax_lower
            or "mitre att&ck" in syntax_lower
        ):
            if value.casefold() == "none" and "none" in syntax_lower:
                return
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        if "elf or pe" in syntax_lower:
            accepted_containers = {
                "elf",
                "elf32",
                "elf64",
                "pe",
                "pe32",
                "pe32+",
                "portable executable",
            }
            if value.casefold() in accepted_containers:
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        if "java archive" in syntax_lower or "application/java-archive" in syntax_lower:
            if value.casefold() in {
                "jar",
                "java archive",
                "java archive (jar)",
                "application/java-archive",
            }:
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        exact_hex_chars = re.search(
            r"\b(?:exact|exactly)\s+(\d+)\s+(?:lowercase\s+)?hexadecimal characters?\b",
            syntax_lower,
        )
        if exact_hex_chars:
            char_count = int(exact_hex_chars.group(1))
            pattern = rf"[0-9a-fA-F]{{{char_count}}}"
            if char_count < 1 or not re.fullmatch(pattern, value):
                raise SolverError(f"{answer_id}: value does not match {syntax}")
            if "lowercase" in syntax_lower and value != value.lower():
                raise SolverError(f"{answer_id}: value must use lowercase hexadecimal")
            return
        padded_hex = re.search(
            r"\bexactly\s+(\d+)\s+lowercase hexadecimal digits?\b",
            str(question.get("question", "")),
            re.IGNORECASE,
        )
        if "0x prefix" in syntax_lower and padded_hex:
            char_count = int(padded_hex.group(1))
            if not re.fullmatch(rf"0x[0-9a-f]{{{char_count}}}", value):
                raise SolverError(f"{answer_id}: value does not match {syntax}")
            return
        if "container_runtime token" in syntax_lower:
            if re.fullmatch(
                r"(?:ELF(?:32|64)?|PE(?:32\+?)?)[_ /-](?:CLI|CLR|\.NET)",
                value,
                re.IGNORECASE,
            ):
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        if (
            "architecture label" in syntax_lower
            or "architecture name" in syntax_lower
            or "machine architecture" in syntax_lower
        ):
            if re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+|[A-Za-z][A-Za-z0-9 _().+-]*)", value):
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        if "elf e_type" in syntax_lower:
            if re.fullmatch(r"(?:ET_[A-Z]+|[A-Za-z][A-Za-z0-9 _().+-]*|0x[0-9a-fA-F]+|\d+)", value):
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        if "byte-order name" in syntax_lower or "byte order" in syntax_lower:
            if value.casefold() in {
                "little",
                "big",
                "little endian",
                "big endian",
                "little-endian",
                "big-endian",
                "lsb",
                "msb",
                "ei_data",
                "elfdata2lsb",
                "elfdata2msb",
                "1",
                "2",
                "0x1",
                "0x2",
            }:
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        if "unsigned base-10 integer" in syntax_lower and "literal token none" in syntax_lower:
            if value == "none" or re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
                return
            raise SolverError(f"{answer_id}: value does not match {syntax}")
        patterns = (
            ("32-character hexadecimal md5", r"[A-Fa-f0-9]{32}"),
            ("40-character hexadecimal sha-1", r"[A-Fa-f0-9]{40}"),
            ("64-character hexadecimal", r"[A-Fa-f0-9]{64}"),
            ("lowercase hexadecimal with a 0x prefix", r"0x[0-9a-f]+"),
            (
                "three lowercase words separated by hyphens",
                r"[a-z]+(?:-[a-z]+){2}-\d{2}",
            ),
        )
        for marker, pattern in patterns:
            if marker in syntax_lower:
                if not re.fullmatch(pattern, value):
                    if (
                        marker == "three lowercase words separated by hyphens"
                        and "submit the slug only" in syntax_lower
                        and "final non-empty decoded line" in str(
                            question.get("question", "")
                        ).lower()
                        and re.fullmatch(
                            r"[a-z]+(?:-[a-z]+){2}-\d{2}(?:-[A-Za-z0-9_-]+)+",
                            value,
                        )
                    ):
                        # A decoded warmup line can explicitly include a complete
                        # instructed token after its slug; retain that token when
                        # the caller derives it from the assigned artifact.
                        return
                    raise SolverError(f"{answer_id}: value does not match {syntax}")
                return
        if "hexadecimal with a 0x prefix" in syntax_lower:
            if not re.fullmatch(r"0x[0-9a-f]+", value):
                raise SolverError(f"{answer_id}: value does not match {syntax}")
            return
        raise SolverError(f"{answer_id}: unsupported answer pattern {syntax!r}")
    raise SolverError(f"{answer_id}: unsupported answer format kind {kind!r}")


def run_cli(
    solver: Callable[
        [dict[str, Any], list[pathlib.Path]],
        tuple[dict[str, str], dict[str, str], bool],
    ],
    description: str,
) -> None:
    reexec_in_configured_environment()
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--start", type=pathlib.Path, required=True)
    parser.add_argument(
        "--artifact",
        type=pathlib.Path,
        action="append",
        required=True,
        help="assigned artifact path; pass once per downloaded artifact/delivery",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print answers, per-field reasoning, and replay status; never submits",
    )
    args = parser.parse_args()
    try:
        start = load_start(args.start)
        answers, reasoning, replay = solver(start, args.artifact)
    except SolverError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
    if args.dry_run:
        print(
            json.dumps(
                {
                    "answers": answers,
                    "reasoning": reasoning,
                    "replay": replay,
                    "submissions": 0,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(json.dumps(answers, indent=2, ensure_ascii=False))
