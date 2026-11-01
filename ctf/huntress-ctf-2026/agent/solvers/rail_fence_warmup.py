#!/usr/bin/env python3
"""Decode three-rail Rail Fence warmups and extract the instructed slug."""

from __future__ import annotations

import base64
import codecs
import gzip
import html
import json
import pathlib
import re
import string
import urllib.parse
import zlib
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


SLUG = re.compile(r"\b[a-z]+(?:-[a-z]+){2}-\d{2}\b")
INSTRUCTION_VALUE = re.compile(
    r"^Nice work decoding this warmup!\s+To solve,\s+submit this exact answer "
    r"to the Game Master:\s*(.+?)\s*$"
)
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}
MAX_ZLIB_OUTPUT = 2 * 1024 * 1024
MAX_COUNTED_OUTPUT = 2 * 1024 * 1024


def _decode_counted_comma_string(
    source: str, *, require_instruction: bool = True
) -> str | None:
    """Decode count:character runs separated by commas, including comma data."""
    if not re.match(r"\d+:", source):
        return None
    offset = 0
    decoded: list[str] = []
    output_length = 0
    while offset < len(source):
        count_match = re.match(r"(\d+):", source[offset:])
        if count_match is None:
            raise SolverError("Counted string has a malformed run length")
        count = int(count_match.group(1))
        offset += count_match.end()
        if count < 1 or offset >= len(source):
            raise SolverError("Counted string has an empty or missing character")
        char = source[offset]
        offset += 1
        output_length += count
        if output_length > MAX_COUNTED_OUTPUT:
            raise SolverError("Counted string exceeds the safe decoded size limit")
        decoded.append(char * count)
        if offset < len(source):
            if source[offset] != ",":
                raise SolverError("Counted string run is missing its comma separator")
            offset += 1
            if offset == len(source):
                break
    text = "".join(decoded)
    if require_instruction and not text.startswith("Nice work decoding this warmup!"):
        raise SolverError("Counted string does not decode to a warmup instruction")
    return text


def _zlib_decompress(data: bytes) -> bytes:
    decoder = zlib.decompressobj()
    decoded = decoder.decompress(data, MAX_ZLIB_OUTPUT + 1)
    if (
        len(decoded) > MAX_ZLIB_OUTPUT
        or not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
    ):
        raise ValueError("zlib payload is oversized, truncated, or has trailing data")
    return decoded


def _rail_fence_decode(ciphertext: str, rails: int) -> str:
    if rails < 2:
        raise SolverError("Rail Fence decoding requires at least two rails")
    if not ciphertext:
        return ""

    pattern: list[int] = []
    row = 0
    direction = 1
    for _ in ciphertext:
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    counts = [pattern.count(index) for index in range(rails)]
    rail_text: list[list[str]] = []
    offset = 0
    for count in counts:
        rail_text.append(list(ciphertext[offset : offset + count]))
        offset += count

    decoded: list[str] = []
    for rail in pattern:
        decoded.append(rail_text[rail].pop(0))
    return "".join(decoded)


def _caesar_backward_seven(text: str) -> str:
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    return text.translate(
        str.maketrans(
            lowercase + uppercase,
            lowercase[-7:] + lowercase[:-7] + uppercase[-7:] + uppercase[:-7],
        )
    )


def _rot47(text: str) -> str:
    return "".join(
        chr(33 + ((ord(char) - 33 + 47) % 94))
        if 33 <= ord(char) <= 126
        else char
        for char in text
    )


def _decode_stage(number: int, encoded: str, label: str) -> str:
    try:
        if number == 1:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        if number == 2:
            return codecs.decode(encoded, "rot_13")
        if number == 3:
            return bytes.fromhex(encoded).decode("utf-8")
        if number == 4:
            return bytes(int(token, 2) for token in encoded.split()).decode("utf-8")
        if number == 5:
            return bytes(int(token, 10) for token in encoded.split()).decode("utf-8")
        if number == 6:
            return bytes(int(token, 8) for token in encoded.split()).decode("utf-8")
        if number == 7:
            return urllib.parse.unquote_to_bytes(encoded).decode("utf-8")
        if number == 8:
            return html.unescape(encoded)
        if number == 9:
            fragment = json.loads(encoded)
            if not isinstance(fragment, str):
                raise ValueError("JSON fragment is not text")
            return fragment
        if number == 10:
            return base64.b32decode(encoded, casefold=False).decode("utf-8")
        if number == 11:
            padded = encoded + ("=" * (-len(encoded) % 4))
            return base64.b64decode(padded, validate=True).decode("utf-8")
        if number == 12:
            return encoded[::-1]
        if number == 13:
            return encoded.translate(
                str.maketrans(
                    string.ascii_lowercase + string.ascii_uppercase,
                    string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1],
                )
            )
        if number == 14:
            return _caesar_backward_seven(encoded)
        if number == 15:
            return _rot47(encoded)
        if number == 16:
            morse_text = "".join(MORSE[token] for token in encoded.split())
            return bytes.fromhex(morse_text).decode("utf-8")
        if number == 17:
            nibbles = []
            for token in encoded.split():
                if not re.fullmatch(r"[ab]{5}", token):
                    raise ValueError("Bacon fragment is not five a/b symbols")
                nibble = int(token.translate(str.maketrans({"a": "0", "b": "1"})), 2)
                if nibble > 15:
                    raise ValueError("Bacon fragment exceeds one hexadecimal nibble")
                nibbles.append(f"{nibble:x}")
            hexadecimal = "".join(nibbles)
            if len(hexadecimal) % 2:
                raise ValueError("Bacon fragments do not form complete bytes")
            return bytes.fromhex(hexadecimal).decode("utf-8")
        if number == 18:
            return _rail_fence_decode(encoded, rails=3)
        if number in (19, 20):
            encoded_bytes = bytes.fromhex(encoded)
            expected_bom = b"\xff\xfe" if number == 19 else b"\xfe\xff"
            if not encoded_bytes.startswith(expected_bom):
                order = "UTF-16LE" if number == 19 else "UTF-16BE"
                raise ValueError(f"hexadecimal stage lacks its {order} BOM")
            return encoded_bytes.decode("utf-16").rstrip("\x00")
        if number == 21:
            compressed = base64.b64decode(encoded, validate=True)
            if not compressed.startswith(b"\x1f\x8b"):
                raise ValueError("Base64 stage does not contain gzip data")
            return gzip.decompress(compressed).decode("utf-8")
        if number == 22:
            compressed = base64.b64decode(encoded, validate=True)
            return _zlib_decompress(compressed).decode("utf-8")
        if number == 23:
            return base64.a85decode(encoded.encode("ascii"), adobe=True).decode("utf-8")
        if number == 24:
            decoded = _decode_counted_comma_string(encoded, require_instruction=False)
            if decoded is None:
                raise ValueError("counted comma stage has no count:character runs")
            return decoded
        if number == 25:
            tokens = encoded.split()
            if not tokens or any(
                re.fullmatch(r"U\+[0-9A-Fa-f]{4,6}", token) is None
                for token in tokens
            ):
                raise ValueError("Unicode code-point stage has an invalid token")
            codepoints = [int(token[2:], 16) for token in tokens]
            if any(
                point > 0x10FFFF or 0xD800 <= point <= 0xDFFF
                for point in codepoints
            ):
                raise ValueError("Unicode code-point stage contains a non-scalar value")
            return "".join(chr(point) for point in codepoints)
    except (
        ValueError,
        KeyError,
        UnicodeDecodeError,
        base64.binascii.Error,
        OSError,
        EOFError,
        zlib.error,
    ) as exc:
        raise SolverError(f"{label}: numbered stage {number:02d} is malformed") from exc
    raise SolverError(f"{label}: unsupported numbered stage {number:02d}")


def _instructed_answer(final_line: str, label: str) -> str:
    """Return the complete explicitly instructed value, preserving any suffix."""
    instruction = INSTRUCTION_VALUE.fullmatch(final_line)
    if instruction is None:
        raise SolverError(f"{label}: final decoded line has no recognized answer instruction")

    value = instruction.group(1)
    matches = list(SLUG.finditer(value))
    if len(matches) != 1 or matches[0].start() != 0:
        raise SolverError(
            f"{label}: instructed value must begin with exactly one answer slug"
        )
    return value


def _decode(data: bytes, label: str) -> tuple[str, str]:
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: warmup blob is not UTF-8 text") from exc

    stripped = source.strip()
    counted_text = _decode_counted_comma_string(stripped)
    is_hex = bool(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", stripped))
    is_gzip_base64 = False
    is_zlib_base64 = False
    is_ascii85 = stripped.startswith("<~") and stripped.endswith("~>")
    is_unicode_codepoints = bool(
        re.fullmatch(r"U\+[0-9A-Fa-f]{4,6}(?:\s+U\+[0-9A-Fa-f]{4,6})*", stripped)
    )
    if counted_text is not None:
        decoded = counted_text
        method = (
            "decoded comma-separated count:character runs, consuming the character "
            "after each colon before treating a comma as the next separator"
        )
        fragments = []
    elif is_hex:
        try:
            encoded_bytes = bytes.fromhex(stripped)
            if not encoded_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
                raise ValueError("hexadecimal bytes lack a UTF-16 byte-order mark")
            decoded = encoded_bytes.decode("utf-16").rstrip("\x00")
        except (UnicodeDecodeError, ValueError) as exc:
            raise SolverError(f"{label}: hexadecimal UTF-16 text is malformed") from exc
        byte_order = "UTF-16LE" if encoded_bytes.startswith(b"\xff\xfe") else "UTF-16BE"
        bom = "FF FE" if byte_order == "UTF-16LE" else "FE FF"
        method = f"decoded hexadecimal bytes as {byte_order} using their {bom} BOM"
        fragments = []
    elif is_ascii85:
        try:
            decoded = base64.a85decode(stripped.encode("ascii"), adobe=True).decode(
                "utf-8"
            )
        except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
            raise SolverError(f"{label}: Adobe ASCII85 text is malformed") from exc
        method = "decoded Adobe ASCII85 (Base85) text and selected its final non-empty line"
        fragments = []
    elif is_unicode_codepoints:
        points = [int(token[2:], 16) for token in stripped.split()]
        if any(
            point > 0x10FFFF or 0xD800 <= point <= 0xDFFF
            for point in points
        ):
            raise SolverError(f"{label}: Unicode code-point stream contains a non-scalar value")
        decoded = "".join(chr(point) for point in points)
        method = "decoded explicit U+ hexadecimal Unicode code points"
        fragments = []
    else:
        try:
            compressed = base64.b64decode(stripped, validate=True)
        except (ValueError, base64.binascii.Error):
            compressed = b""
        is_gzip_base64 = compressed.startswith(b"\x1f\x8b")
        if is_gzip_base64:
            try:
                decoded = gzip.decompress(compressed).decode("utf-8")
            except (OSError, EOFError, UnicodeDecodeError) as exc:
                raise SolverError(f"{label}: Base64-wrapped gzip text is malformed") from exc
            method = "decoded Base64-wrapped gzip UTF-8 text"
            fragments = []
        elif (
            len(compressed) >= 2
            and compressed[0] & 0x0F == 8
            and compressed[0] >> 4 <= 7
            and int.from_bytes(compressed[:2], "big") % 31 == 0
        ):
            try:
                decoded = _zlib_decompress(compressed).decode("utf-8")
            except (ValueError, UnicodeDecodeError, zlib.error) as exc:
                raise SolverError(f"{label}: Base64-wrapped zlib text is malformed") from exc
            is_zlib_base64 = True
            method = "decoded Base64-wrapped zlib-compressed UTF-8 text"
            fragments = []
        else:
            fragments = []
            for line in source.splitlines():
                if not line.strip():
                    continue
                match = re.fullmatch(r"(\d{2})\t(.*)", line)
                if match is None:
                    fragments = []
                    break
                fragments.append((int(match.group(1)), match.group(2)))

    if fragments:
        expected = list(range(1, len(fragments) + 1))
        actual = [number for number, _ in fragments]
        if actual != expected or actual[-1] not in (18, 19, 20, 21, 22, 23, 24, 25):
            raise SolverError(f"{label}: numbered stages are missing or out of order")
        decoded = "".join(
            _decode_stage(number, encoded, label) for number, encoded in fragments
        )
        if actual[-1] == 24:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, decoded hexadecimal UTF-16LE and UTF-16BE at stages 19–20, Base64-wrapped gzip at stage 21, Base64-wrapped zlib at stage 22, Adobe ASCII85 at stage 23, and comma-separated count:character runs at stage 24"
        elif actual[-1] == 25:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, decoded hexadecimal UTF-16LE and UTF-16BE at stages 19–20, Base64-wrapped gzip at stage 21, Base64-wrapped zlib at stage 22, Adobe ASCII85 at stage 23, comma-separated count:character runs at stage 24, and explicit U+ hexadecimal Unicode code points at stage 25"
        elif actual[-1] == 23:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, decoded hexadecimal UTF-16LE and UTF-16BE at stages 19–20, Base64-wrapped gzip at stage 21, Base64-wrapped zlib at stage 22, and Adobe ASCII85 at stage 23"
        elif actual[-1] == 21:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, decoded hexadecimal UTF-16LE with its BOM at stage 19 and hexadecimal UTF-16BE with its BOM at stage 20, then decoded Base64-wrapped gzip UTF-8 text at stage 21"
        elif actual[-1] == 22:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, decoded hexadecimal UTF-16LE with its BOM at stage 19 and hexadecimal UTF-16BE with its BOM at stage 20, decoded Base64-wrapped gzip UTF-8 text at stage 21, then decoded Base64-wrapped zlib UTF-8 text at stage 22"
        elif actual[-1] == 20:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, decoded hexadecimal UTF-16LE with its BOM at stage 19, and hexadecimal UTF-16BE with its BOM at stage 20"
        elif actual[-1] == 19:
            method = "decoded numbered stages 01–17, applied three-rail Rail Fence at stage 18, then decoded hexadecimal UTF-16LE with its BOM at stage 19"
        else:
            method = "decoded numbered stages 01–17, then applied three-rail Rail Fence at stage 18"
    elif (
        not is_hex
        and not is_gzip_base64
        and not is_zlib_base64
        and not is_ascii85
        and not is_unicode_codepoints
        and counted_text is None
    ):
        decoded = _rail_fence_decode(source, rails=3)
        method = "decoded three-rail zigzag text"

    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        raise SolverError(f"{label}: decoded warmup has no nonempty lines")
    value = _instructed_answer(lines[-1], label)
    detail = f"{method}; selected its final nonempty line"
    if SLUG.fullmatch(value) is None:
        detail += " and preserved the complete instructed value after its slug"
    return value, detail


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    members = [
        member
        for path, payload in load_artifacts(artifact_paths)
        for member in iter_zip_files(payload, path.name)
    ]

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        hint = artifact_hint(question).strip()
        if not hint:
            if len(members) != 1:
                raise SolverError(f"{answer_id}: no hint selects one warmup blob")
            label, data = members[0]
        else:
            member_hint = hint.rsplit("->", 1)[-1].strip()
            try:
                label, data = unique_by_hint(
                    members, member_hint, description=f"warmup blob for {answer_id}"
                )
            except SolverError:
                if len(members) != 1 or len(artifact_paths) != 1:
                    raise
                label, data = members[0]

        value, detail = _decode(data, label)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = f"{label}: {detail}"
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Decode a three-rail Rail Fence warmup")


if __name__ == "__main__":
    main()
