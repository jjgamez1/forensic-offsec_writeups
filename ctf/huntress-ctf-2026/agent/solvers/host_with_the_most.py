#!/usr/bin/env python3
"""Statically analyze the assigned PowerShell and JScript evidence bundle."""

from __future__ import annotations

import base64
import binascii
import io
import json
import pathlib
import re
import urllib.parse
import zipfile
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    artifact_hint,
    answer_ids_and_replay,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)
from agent.solvers.powershell_triage import (
    ARCHIVE_PASSWORD,
    answer_semantic,
    classify as classify_powershell,
    decode_descriptor as decode_powershell_descriptor,
)


ROLE_ATTACK = {
    "benign_utility": "none",
    "stager": "T1105",
    "dropper": "T1140",
    "downloader": "T1105",
    "uploader": "T1041",
    "launcher": "T1059.007",
    "impact": "T1486",
    "staged_chain": "T1059.007",
    "relay": "T1059.007",
    "persistence_descriptor": "T1053.005",
}
JSCRIPT_SUFFIXES = (
    "function-style",
    "invocation-style",
    "property-style",
    "next-stage",
    "extension",
    "campaign",
    "adapter",
    "host",
    "attack",
    "role",
    "url",
    "path",
    "note",
)


def _archive_members(
    data: bytes,
    label: str,
    *,
    depth: int = 0,
) -> list[tuple[str, bytes]]:
    if depth > 8:
        raise SolverError("Nested ZIP depth exceeds the static inspection limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            encrypted = any(info.flag_bits & 1 for info in infos)
    except zipfile.BadZipFile:
        return [(label, data)]

    if encrypted:
        try:
            import pyzipper
        except ImportError as exc:
            raise SolverError(
                "This assigned AES ZIP requires pyzipper in the configured Python environment"
            ) from exc
        try:
            with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
                archive.pwd = ARCHIVE_PASSWORD.encode("utf-8")
                members = [
                    (f"{label}/{info.filename}", archive.read(info))
                    for info in archive.infolist()
                    if not info.is_dir()
                ]
        except (RuntimeError, ValueError, OSError, zipfile.BadZipFile) as exc:
            raise SolverError(f"Could not read assigned AES ZIP {label}") from exc
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [
                (f"{label}/{info.filename}", archive.read(info))
                for info in archive.infolist()
                if not info.is_dir()
            ]

    leaves: list[tuple[str, bytes]] = []
    for member_label, member_data in members:
        leaves.extend(
            _archive_members(member_data, member_label, depth=depth + 1)
        )
    return leaves


def collect_members(paths: list[pathlib.Path]) -> tuple[
    list[tuple[str, bytes]], list[list[tuple[str, bytes]]]
]:
    all_members: list[tuple[str, bytes]] = []
    by_artifact = []
    for path, data in load_artifacts(paths):
        members = _archive_members(data, path.name)
        by_artifact.append(members)
        all_members.extend(members)
    if not all_members:
        raise SolverError("No readable files were found in the assigned ZIP artifacts")
    return all_members, by_artifact


def _recover_section(source: str, function_name: str) -> str:
    patterns = (
        rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{",
        rf"\bvar\s+{re.escape(function_name)}\s*=\s*function(?:\s+[A-Za-z_$][\w$]*)?\s*\([^)]*\)\s*\{{",
    )
    match = next((re.search(pattern, source) for pattern in patterns if re.search(pattern, source)), None)
    if match is None:
        raise SolverError(f"{function_name}: recovery function was not found")
    following = re.search(
        r"(?m)^\s*(?:var\s+)?inspect_[A-Za-z0-9_$]+\s*(?:=|\()",
        source[match.end():],
    )
    return source[match.end(): match.end() + following.start()] if following else source[match.end():]


def _js_string_literals(expression: str) -> str:
    literals = re.findall(r'"(?:\\.|[^"\\])*"', expression)
    if not literals:
        raise SolverError("JScript packed text has no literal string payload")
    try:
        return "".join(json.loads(literal) for literal in literals)
    except json.JSONDecodeError as exc:
        raise SolverError("JScript packed text contains an invalid string literal") from exc


def decode_javascript_descriptor(source: str) -> dict[str, Any]:
    recover_names = re.findall(
        r"(?:\bfunction\s+(recover_[A-Za-z0-9_$]+)\s*\(|"
        r"\bvar\s+(recover_[A-Za-z0-9_$]+)\s*=\s*function)",
        source,
    )
    names = [left or right for left, right in recover_names]
    if len(names) != 1:
        raise SolverError("JScript sample must expose exactly one recovery function")
    section = _recover_section(source, names[0])

    packed_match = re.search(r"\bvar\s+packedText\s*=\s*(.*?);", source, re.DOTALL)
    if packed_match:
        packed = _js_string_literals(packed_match.group(1))
        if re.fullmatch(r"(?:%[0-9a-fA-F]{2})+", packed):
            encoded = urllib.parse.unquote_to_bytes(packed)
        elif re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})+", packed):
            encoded = bytes(int(item, 16) for item in packed.split(":"))
        elif re.fullmatch(r"\d+(?:-\d+)+", packed):
            numbers = [int(item, 10) for item in packed.split("-")]
            if any(number < 0 or number > 255 for number in numbers):
                raise SolverError("JScript decimal byte is outside the valid range")
            encoded = bytes(numbers)
        else:
            try:
                encoded = base64.b64decode(packed, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise SolverError("JScript packed text is not a supported static encoding") from exc
    else:
        array_matches = re.findall(
            r"\bvar\s+([A-Za-z_$][\w$]*)\s*=\s*\[([0-9a-fA-FxX,\s]+)\]",
            source,
        )
        payload_arrays = [
            (name, array_text)
            for name, array_text in array_matches
            if not re.search(r"key", name, re.IGNORECASE)
            and len(array_text.split(",")) >= 16
        ]
        if not payload_arrays:
            raise SolverError("JScript recovery function has no recognized literal payload")
        numbers = [
            (
                int(number.strip(), 16)
                if number.strip().lower().startswith("0x")
                else int(number.strip(), 10)
            )
            for name, array_text in payload_arrays
            for number in array_text.split(",")
            if number.strip()
        ]
        if not numbers:
            raise SolverError("JScript recovery function has no numeric payload bytes")
        if any(number < 0 or number > 255 for number in numbers):
            raise SolverError("JScript literal payload byte is outside the valid range")
        encoded = bytes(numbers)

    if source.count(".reverse()") % 2:
        encoded = encoded[::-1]
    offset_match = re.search(
        r"\[\s*i\s*\]\s*([+-])\s*(\d+)(?:\s*\+\s*256)?\s*\)?\s*%\s*256",
        source,
    )
    if offset_match:
        offset = int(offset_match.group(2))
        if offset_match.group(1) == "-":
            encoded = bytes((value - offset) % 256 for value in encoded)
        else:
            encoded = bytes((value + offset) % 256 for value in encoded)
    previous_match = re.search(r"\bvar\s+previous\s*=\s*(\d+)", source)
    if previous_match and re.search(
        r"\[\s*i\s*\]\s*\^\s*previous\s*\)\s*;\s*previous\s*=\s*[A-Za-z_$][\w$]*\s*\[\s*i\s*\]",
        source,
    ):
        previous = int(previous_match.group(1))
        transformed = bytearray()
        for value in encoded:
            transformed.append(value ^ previous)
            previous = value
        encoded = bytes(transformed)
    key_match = re.search(
        r"\bvar\s+keyBytes\s*=\s*\[([0-9,\s]+)\]", source
    )
    scalar_match = re.search(r"\^\s*(\d+)", source)
    if key_match:
        key = bytes(int(number) for number in re.findall(r"\d+", key_match.group(1)))
        if not key:
            raise SolverError("JScript XOR key is empty")
        encoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
    elif scalar_match:
        key_value = int(scalar_match.group(1))
        encoded = bytes(value ^ key_value for value in encoded)

    try:
        descriptor = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError("Statically decoded JScript payload is not UTF-8 JSON") from exc
    if not isinstance(descriptor, dict):
        raise SolverError("JScript recovery payload is not a JSON object")
    return descriptor


def _inspect_function_style(source: str) -> tuple[str, str, str]:
    declaration = re.search(
        r"(?m)^\s*function\s+(inspect_[A-Za-z0-9_$]+)\s*\(", source
    )
    if declaration:
        inspect_name = declaration.group(1)
        style = "declaration"
    else:
        expression = re.search(
            r"(?m)^\s*var\s+(inspect_[A-Za-z0-9_$]+)\s*=\s*function"
            r"(?:\s+([A-Za-z0-9_$]+))?\s*\(",
            source,
        )
        if not expression:
            raise SolverError("JScript inspect function declaration was not identified")
        inspect_name = expression.group(1)
        style = "named_expression" if expression.group(2) else "anonymous_expression"

    opening = source.find("{", declaration.end() if declaration else expression.end())
    if opening < 0:
        raise SolverError("JScript inspect function body was not found")
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    body_end = None
    index = opening
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
        elif block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"'", '"', "`"}:
            quote = character
        elif character == "/" and following == "/":
            line_comment = True
            index += 1
        elif character == "/" and following == "*":
            block_comment = True
            index += 1
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                body_end = index + 1
                break
        index += 1
    if body_end is None:
        raise SolverError("JScript inspect function body is not balanced")
    body = source[opening:body_end]

    invocation = re.search(
        rf"\b(recover_[A-Za-z0-9_$]+)\s*(?:\.\s*(call|apply)\s*\(|\s*\()",
        body,
    )
    if not invocation:
        raise SolverError("JScript recovery invocation style was not identified")
    invocation_style = invocation.group(2) or "direct"

    recovered_variable = re.search(
        rf"\bvar\s+([A-Za-z_$][\w$]*)\s*=\s*eval\s*\([^;\n]*"
        rf"\brecover_[A-Za-z0-9_$]+\s*(?:\.\s*(?:call|apply)\s*\(|\s*\()",
        body,
    )
    if not recovered_variable:
        raise SolverError("JScript recovered descriptor variable was not identified")
    variable = recovered_variable.group(1)
    dot_access = re.findall(
        rf"\b{re.escape(variable)}\s*\.\s*(?:steps|adapter|values|stageCount)\b",
        body,
    )
    bracket_access = re.findall(
        rf"\b{re.escape(variable)}\s*\[\s*(['\"])(?:steps|adapter|values|stageCount)\1\s*\]",
        body,
    )
    if dot_access and bracket_access:
        property_style = "mixed"
    elif dot_access:
        property_style = "dot"
    elif bracket_access:
        property_style = "bracket_literal"
    else:
        raise SolverError("JScript recovered descriptor property accesses were not found")
    return style, invocation_style, property_style


def classify_javascript(descriptor: dict[str, Any]) -> tuple[str, str]:
    steps = descriptor.get("steps")
    if not isinstance(steps, list) or not all(isinstance(step, str) for step in steps):
        raise SolverError("JScript descriptor has no ordered string behavior graph")
    if steps == ["decode_configuration", "return_configuration"]:
        role = "benign_utility"
    elif steps and steps[-1] == "dispatch_next_stage":
        role = "relay"
    elif steps and steps[-1] == "handoff_script":
        role = "staged_chain"
    elif (
        steps
        and steps[-1] == "dispatch_process"
        and "profile_host" in steps
        and "acquire_remote" in steps
        and "write_file" in steps
    ):
        role = "staged_chain"
    elif steps and steps[-1] in {"upload_remote", "transmit_remote"}:
        role = "uploader"
    elif (
        "transform_content" in steps or "transform_copy" in steps
    ) and steps[-1] == "write_recovery_note":
        role = "impact"
    elif "build_schedule" in steps and "register_descriptor" in steps:
        role = "persistence_descriptor"
    elif "locate_local" in steps and "dispatch_process" in steps:
        role = "launcher"
    elif "decode_embedded" in steps and steps[-1] == "write_file":
        role = "dropper"
    elif "acquire_remote" in steps and steps[-1] in {
        "dispatch_memory",
        "dispatch_pipe",
    }:
        role = "stager"
    elif "acquire_remote" in steps and steps[-1] == "write_file":
        role = "downloader"
    else:
        raise SolverError("JScript ordered graph does not match a returned role definition")
    return role, ROLE_ATTACK[role]


def _jscript_field_value(
    answer_id: str,
    descriptor: dict[str, Any],
    style_data: tuple[str, str, str],
) -> str:
    suffix = next(
        (item for item in JSCRIPT_SUFFIXES if answer_id.endswith("-" + item)),
        None,
    )
    if suffix is None:
        raise SolverError(f"{answer_id}: unknown JScript answer field")
    role, attack = classify_javascript(descriptor)
    values = descriptor.get("values", {})
    if not isinstance(values, dict):
        raise SolverError(f"{answer_id}: descriptor values field is not an object")
    direct = {
        "role": role,
        "attack": attack,
        "adapter": descriptor.get("adapter"),
        "campaign": values.get("campaign_id"),
        "host": values.get("host_id"),
        "url": values.get("url"),
        "path": values.get("file_path"),
        "next-stage": values.get("next_stage"),
        "extension": values.get("extension"),
        "note": values.get("note_name"),
        "function-style": style_data[0],
        "invocation-style": style_data[1],
        "property-style": style_data[2],
    }
    value = direct[suffix]
    return "none" if value is None else str(value)


def _jscript_role_name(answer_id: str) -> str:
    _, field = parse_answer_id(answer_id)
    match = re.match(r"^jscript-([a-z]+)-", field)
    if not match:
        raise SolverError(f"{answer_id}: JScript sample category was not identified")
    return match.group(1)


def _solve_ps_field(
    answer_id: str,
    question: dict[str, Any],
    sample_answers: dict[str, dict[str, Any]],
    sample_path: str,
) -> tuple[str, str]:
    semantic = answer_semantic(question, answer_id)
    value = sample_answers[sample_path].get(semantic)
    if not isinstance(value, str) or not value:
        raise SolverError(f"{answer_id}: artifact does not determine {semantic}")
    return value, f"Decoded the assigned PowerShell Base64 JSON and classified its static type references to derive {semantic} from {sample_path}."


def _hinted_sample(
    question: dict[str, Any],
    candidates: list[tuple[str, bytes]],
    answer_id: str,
) -> tuple[str, bytes]:
    hint_text = artifact_hint(question)
    if "->" in hint_text:
        archive_hint, member_hint = (
            part.strip().replace("\\", "/")
            for part in hint_text.rsplit("->", 1)
        )
        archive_name = pathlib.PurePosixPath(archive_hint).name
        scoped_hint = f"{archive_name}/{member_hint}"
        matches = [
            item
            for item in candidates
            if item[0].replace("\\", "/").endswith("/" + scoped_hint)
            or item[0].replace("\\", "/") == scoped_hint
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise SolverError(
                f"{answer_id}: artifact hint {hint_text!r} selects multiple assigned files"
            )
        return unique_by_hint(
            candidates, member_hint, description=f"artifact for {answer_id}"
        )
    member_hint = pathlib.PurePosixPath(hint_text).name
    return unique_by_hint(
        candidates, member_hint, description=f"artifact for {answer_id}"
    )


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    all_members, members_by_artifact = collect_members(artifact_paths)

    refs = {}
    for answer_id in answer_ids:
        match = re.search(
            r"\bdelivery\s+(\d+)\b",
            artifact_hint(questions[answer_id]),
            re.IGNORECASE,
        )
        refs[answer_id] = max(0, int(match.group(1)) - 1) if match else None
    ordered_refs = sorted({item for item in refs.values() if item is not None})
    if ordered_refs and len(ordered_refs) != len(artifact_paths):
        raise SolverError(
            "Cannot map assigned archive deliveries to the returned artifact hints"
        )

    ps_cache: dict[str, dict[str, Any]] = {}
    js_cache: dict[str, tuple[dict[str, Any], tuple[str, str, str]]] = {}
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        delivery_ref = refs[answer_id]
        scoped = all_members
        if len(artifact_paths) > 1:
            if delivery_ref is None:
                raise SolverError(f"{answer_id}: multi-delivery question has no delivery hint")
            scoped = members_by_artifact[ordered_refs.index(delivery_ref)]

        member_path, member_bytes = _hinted_sample(
            question, scoped, answer_id
        )

        if member_path.lower().endswith(".ps1"):
            if member_path not in ps_cache:
                try:
                    source = member_bytes.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise SolverError(f"{member_path}: PowerShell sample is not UTF-8") from exc
                descriptor, native_types = decode_powershell_descriptor(
                    source, member_path
                )
                ps_cache[member_path] = classify_powershell(
                    descriptor, native_types
                )
            value, explanation = _solve_ps_field(
                answer_id, question, ps_cache, member_path
            )
        elif member_path.lower().endswith(".js"):
            if member_path not in js_cache:
                try:
                    source = member_bytes.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise SolverError(f"{member_path}: JScript sample is not UTF-8") from exc
                descriptor = decode_javascript_descriptor(source)
                js_cache[member_path] = (
                    descriptor,
                    _inspect_function_style(source),
                )
            descriptor, style_data = js_cache[member_path]
            value = _jscript_field_value(answer_id, descriptor, style_data)
            explanation = (
                f"Statically decoded the literal recovery payload in {member_path}, "
                "read its ordered behavior graph and values, and inspected the "
                "function/invocation/property syntax without executing the script."
            )
        else:
            raise SolverError(
                f"{answer_id}: hinted member is not a supported .ps1 or .js sample"
            )

        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = explanation

    return answers, reasoning, replay


def solve(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically analyze Host With the Most evidence")


if __name__ == "__main__":
    main()
