#!/usr/bin/env python3
"""Decode the Day 8 warmup and inspect its metadata evidence archive."""

from __future__ import annotations

import hashlib
import html
import io
import json
import pathlib
import re
import struct
import zipfile
import base64
import codecs
import urllib.parse
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)
from agent.answer_ids import parse_answer_id
from agent.solvers.jpeg_structure import jpeg_sof_dimensions
from agent.solvers.rail_fence_warmup import _decode_stage


def _archive_members(
    paths: list[pathlib.Path],
) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []

    def walk(data: bytes, label: str, depth: int = 0) -> None:
        if depth > 8:
            raise SolverError("Nested ZIP depth exceeds the inspection limit")
        if not data.startswith(b"PK\x03\x04"):
            result.append((label, data))
            return
        if depth:
            result.append((label, data))
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for entry in archive.infolist():
                    if entry.is_dir():
                        continue
                    child = archive.read(entry)
                    walk(child, f"{label}/{entry.filename}", depth + 1)
        except (zipfile.BadZipFile, RuntimeError) as exc:
            raise SolverError(f"Could not inspect assigned ZIP member {label}") from exc

    for path, data in load_artifacts(paths):
        walk(data, path.name)
    return result


def _png_dimensions(data: bytes, label: str) -> tuple[int, int]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 24:
        raise SolverError(f"{label}: PNG signature or IHDR is truncated")
    if data[12:16] != b"IHDR" or struct.unpack_from(">I", data, 8)[0] != 13:
        raise SolverError(f"{label}: first PNG chunk is not a 13-byte IHDR")
    width, height = struct.unpack_from(">II", data, 16)
    if width == 0 or height == 0:
        raise SolverError(f"{label}: PNG dimensions are zero")
    return width, height


def _metadata_answers(
    start: dict[str, Any],
    answer_ids: list[str],
    paths: list[pathlib.Path],
    questions: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], dict[str, str]]:
    members = _archive_members(paths)
    answers: dict[str, str] = {}
    evidence: dict[str, str] = {}

    top_level_names = {
        str(item.get("filename"))
        for item in start.get("artifacts", [])
        if isinstance(item, dict) and isinstance(item.get("filename"), str)
    }

    def hinted_member(
        answer_id: str, fallback_name: str, description: str
    ) -> tuple[str, bytes]:
        hint = artifact_hint(questions[answer_id]).replace("\\", "/").strip()
        if not hint:
            return unique_by_hint(members, fallback_name, description=description)
        archive_hint, separator, member_hint = hint.partition("->")
        archive_hint = archive_hint.strip()
        member_hint = member_hint.strip()
        # In Single Solve the returned artifact itself is the named evidence
        # archive, while Mastery nests each named evidence archive in one bundle.
        if archive_hint in top_level_names:
            return unique_by_hint(
                members,
                member_hint if separator else fallback_name,
                description=description,
            )
        scoped_archive = [
            item
            for item in members
            if f"/{archive_hint}/" in item[0].replace("\\", "/")
        ]
        if not scoped_archive:
            raise SolverError(
                f"{answer_id}: artifact hint {archive_hint!r} does not resolve "
                "inside the assigned ZIP"
            )
        if separator:
            return unique_by_hint(
                scoped_archive,
                member_hint,
                description=description,
            )
        return unique_by_hint(
            scoped_archive,
            fallback_name,
            description=description,
        )

    for answer_id in answer_ids:
        field = parse_answer_id(answer_id)[1]
        if field == "evidence-note-filename":
            note_label, note = hinted_member(
                answer_id, "evidence-note.txt", "first evidence note"
            )
            value, source = pathlib.PurePosixPath(note_label).name, note_label
        elif field in {
            "evidence-note-size-bytes",
            "evidence-note-md5",
            "evidence-note-sha1",
            "evidence-note-sha256",
            "evidence-note-magic-prefix-hex-16",
            "evidence-note-text-utf8-bom-present",
        }:
            note_label, note = hinted_member(
                answer_id, "evidence-note.txt", "evidence note"
            )
            source = note_label
            if field == "evidence-note-size-bytes":
                value = str(len(note))
            elif field == "evidence-note-md5":
                value = hashlib.md5(note).hexdigest()
            elif field == "evidence-note-sha1":
                value = hashlib.sha1(note).hexdigest()
            elif field == "evidence-note-sha256":
                value = hashlib.sha256(note).hexdigest()
            elif field == "evidence-note-magic-prefix-hex-16":
                value = note[:16].hex()
            else:
                value = "true" if note.startswith(b"\xef\xbb\xbf") else "false"
        elif field == "d04-jpeg-001-jpeg-sof-dimensions-pixels":
            jpeg_label, jpeg = hinted_member(answer_id, "camera-001.jpg", "JPEG specimen")
            width, height = jpeg_sof_dimensions(jpeg)
            value, source = f"{width}x{height}", jpeg_label
        elif field == "d05-png-001-png-ihdr-dimensions-pixels":
            png_label, png = hinted_member(answer_id, "panel-001.png", "PNG specimen")
            width, height = _png_dimensions(png, png_label)
            value, source = f"{width}x{height}", png_label
        elif field == "d06-pdf-001-pdf-header-version":
            pdf_label, pdf = hinted_member(answer_id, "document-001.pdf", "PDF specimen")
            if not pdf.startswith(b"%PDF-"):
                raise SolverError(f"{pdf_label}: PDF header is missing")
            value, source = pdf[5:].splitlines()[0].decode("ascii"), pdf_label
        elif field == "d07-zip-001-zip-eocd-total-entries":
            zip_label, zip_bytes = hinted_member(
                answer_id, "evidence-drop-001.zip", "nested ZIP specimen"
            )
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
                    value = str(len(archive.infolist()))
            except zipfile.BadZipFile as exc:
                raise SolverError(f"{zip_label}: invalid ZIP archive") from exc
            source = f"{zip_label}: central-directory entry count"
        elif field == "d07-zip-001-zip-central-directory-member-names":
            zip_label, zip_bytes = hinted_member(
                answer_id, "evidence-drop-001.zip", "nested ZIP specimen"
            )
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
                    names = archive.namelist()
            except zipfile.BadZipFile as exc:
                raise SolverError(f"{zip_label}: invalid ZIP archive") from exc
            value = json.dumps(names, separators=(",", ":"), ensure_ascii=False)
            source = f"{zip_label}: central-directory names in stored order"
        else:
            raise SolverError(f"{answer_id}: no static evidence mapping is defined")
        answers[answer_id] = value
        evidence[answer_id] = source
    return answers, evidence


def _decode_warmup_blob(data: bytes, label: str) -> tuple[str, str]:
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: warmup blob is not UTF-8 text") from exc
    lines = [line.strip() for line in source.splitlines() if line.strip()]
    if not lines:
        raise SolverError(f"{label}: assigned warmup artifact is empty")
    morse_tokens = source.split()
    if morse_tokens and all(re.fullmatch(r"[.-]+", token) for token in morse_tokens):
        morse_to_text = {
            ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
            "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
            "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
            ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
            "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
            "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
            "...--": "3", "....-": "4", ".....": "5", "-....": "6",
            "--...": "7", "---..": "8", "----.": "9",
        }
        try:
            hexadecimal = "".join(morse_to_text[token] for token in morse_tokens)
            if not re.fullmatch(r"(?:[0-9A-F]{2})+", hexadecimal):
                raise ValueError("Morse text is not an even-length hexadecimal string")
            decoded = bytes.fromhex(hexadecimal).decode("utf-8")
        except (KeyError, UnicodeDecodeError, ValueError) as exc:
            raise SolverError(f"{label}: Morse-coded hexadecimal bytes are malformed") from exc
        method = "Morse characters, hexadecimal bytes, and UTF-8"
    else:
        encoded_fragments = []
        tagged_lines = True
        for line in lines:
            match = re.fullmatch(r"(\d{2})\t(.*)", line)
            if match is None:
                tagged_lines = False
                break
            encoded_fragments.append((int(match.group(1)), match.group(2)))
        if tagged_lines:
            expected = list(range(1, len(encoded_fragments) + 1))
            actual = [number for number, _ in encoded_fragments]
            if actual != expected:
                raise SolverError(f"{label}: numbered transformations are missing or out of order")
            decoded_parts: list[str] = []
            for number, encoded in encoded_fragments:
                try:
                    if number == 1:
                        part = base64.b64decode(encoded, validate=True).decode("utf-8")
                    elif number == 2:
                        part = codecs.decode(encoded, "rot_13")
                    elif number == 3:
                        part = bytes.fromhex(encoded).decode("utf-8")
                    elif number == 4:
                        octets = [int(token, 2) for token in encoded.split()]
                        part = bytes(octets).decode("utf-8")
                    elif number == 5:
                        octets = [int(token, 10) for token in encoded.split()]
                        part = bytes(octets).decode("utf-8")
                    elif number == 6:
                        octets = [int(token, 8) for token in encoded.split()]
                        part = bytes(octets).decode("utf-8")
                    elif number == 7:
                        part = urllib.parse.unquote_to_bytes(encoded).decode("utf-8")
                    elif number == 8:
                        part = html.unescape(encoded)
                    elif number == 9:
                        part = json.loads(encoded)
                        if not isinstance(part, str):
                            raise ValueError("JSON escape fragment is not a string")
                    elif number == 10:
                        part = base64.b32decode(encoded, casefold=False).decode("utf-8")
                    elif 11 <= number <= 18:
                        part = _decode_stage(number, encoded, label)
                    else:
                        raise SolverError(
                            f"{label}: unsupported numbered encoding {number:02d}"
                        )
                except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
                    raise SolverError(
                        f"{label}: numbered encoding {number:02d} is malformed"
                    ) from exc
                decoded_parts.append(part)
            decoded = "".join(decoded_parts)
            method = (
                f"numbered warmup encoding fragments through stage {actual[-1]:02d}"
            )
        else:
            stripped = source.strip()
            if stripped.startswith('"') and stripped.endswith('"'):
                try:
                    decoded = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise SolverError(f"{label}: JSON-escaped warmup text is malformed") from exc
                if not isinstance(decoded, str):
                    raise SolverError(f"{label}: JSON warmup value is not text")
                method = "JSON string escapes"
            elif re.fullmatch(r"[A-Z2-7]+={0,6}", stripped):
                try:
                    decoded = base64.b32decode(stripped, casefold=False).decode("utf-8")
                except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
                    raise SolverError(f"{label}: Base32 warmup text is malformed") from exc
                method = "Base32"
            else:
                decoded = html.unescape(source)
                method = "HTML numeric character references"
    decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not decoded_lines:
        raise SolverError(f"{label}: decoded warmup artifact has no nonempty line")
    final_line = decoded_lines[-1]
    matches = re.findall(r"\b[a-z]+(?:-[a-z]+){2}-\d{2}\b", final_line)
    if len(matches) != 1:
        raise SolverError(
            f"{label}: final decoded line does not contain exactly one answer slug"
        )
    slug = matches[0]
    tail = final_line[final_line.find(slug) + len(slug) :].strip()
    if tail:
        delimiter = final_line.rfind(":")
        instructed = final_line[delimiter + 1 :].strip() if delimiter >= 0 else ""
        if not instructed.startswith(slug) or instructed == slug:
            raise SolverError(
                f"{label}: text follows the slug, but the full instructed answer "
                "cannot be isolated from the final decoded line"
            )
        return instructed, (
            f"{method}; final nonempty decoded line instructed {instructed!r} "
            f"after the slug {slug!r}"
        )
    return slug, f"{method}; final nonempty decoded line contains only the slug"


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    if all(parse_answer_id(answer_id)[1] == "message" for answer_id in answer_ids):
        members = _archive_members(artifact_paths)
        answers: dict[str, str] = {}
        evidence: dict[str, str] = {}
        for answer_id in answer_ids:
            hint = str(questions[answer_id].get("artifact", "")).strip()
            if hint:
                try:
                    label, data = unique_by_hint(
                        members, hint, description=f"warmup blob for {answer_id}"
                    )
                except SolverError:
                    if len(artifact_paths) != 1 or artifact_paths[0].read_bytes().startswith(
                        b"PK\x03\x04"
                    ):
                        raise
                    label, data = artifact_paths[0].name, artifact_paths[0].read_bytes()
            elif len(artifact_paths) == 1 and not artifact_paths[0].read_bytes().startswith(
                b"PK\x03\x04"
            ):
                label, data = artifact_paths[0].name, artifact_paths[0].read_bytes()
            elif len(members) == 1:
                label, data = members[0]
            else:
                raise SolverError(
                    f"{answer_id}: question does not identify one assigned warmup blob"
                )
            value, method = _decode_warmup_blob(data, label)
            answers[answer_id] = value
            evidence[answer_id] = f"{label}: {method}"
    else:
        answers, evidence = _metadata_answers(
            start, answer_ids, artifact_paths, questions
        )
    for answer_id, value in answers.items():
        validate_answer_format(answer_id, value, questions[answer_id])
    return answers, evidence, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Decode the Day 8 warmup and inspect metadata evidence")


if __name__ == "__main__":
    main()
