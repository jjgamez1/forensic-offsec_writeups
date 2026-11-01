#!/usr/bin/env python3
"""Statically recover descriptors from PowerShell, JScript, batch, and VBScript."""

from __future__ import annotations

import base64
import pathlib
import re
import urllib.parse
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    artifact_hint,
    answer_ids_and_replay,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)
from agent.solvers.host_with_the_most import (
    _jscript_field_value,
    _inspect_function_style,
    classify_javascript,
    collect_members,
    decode_javascript_descriptor,
)
from agent.solvers.powershell_triage import (
    answer_semantic,
    classify as classify_powershell,
    decode_descriptor as decode_powershell_descriptor,
)


LANGUAGE_ATTACK = {
    "launcher": {"js": "T1059.007", "vbs": "T1059.005", "cmd": "T1059.003", "bat": "T1059.003", "bash": "T1059.004"},
    "staged_chain": {"js": "T1059.007", "vbs": "T1059.005", "cmd": "T1059.003", "bat": "T1059.003", "bash": "T1059.004"},
    "relay": {"js": "T1059.007", "vbs": "T1059.005", "cmd": "T1059.003", "bat": "T1059.003", "bash": "T1059.004"},
    "stager": {"bash": "T1105"},
    "dropper": {"bash": "T1140"},
    "downloader": {"bash": "T1105"},
    "uploader": {"bash": "T1041"},
    "impact": {"bash": "T1486"},
    "benign_utility": {"bash": "none"},
}


def _vbs_material(source: str, filename: str) -> tuple[bytes, str, str, str]:
    material = re.search(
        r'(?im)^\s*Const\s+Material_[A-Za-z0-9_]+\s*=\s*"([^"]*)"',
        source,
    )
    codec = re.search(
        r'(?im)^\s*Const\s+Codec_[A-Za-z0-9_]+\s*=\s*"([^"]*)"',
        source,
    )
    if material is None or codec is None:
        raise SolverError(f"{filename}: VBScript material/codec constants are missing")
    parts = codec.group(1).split("|")
    if len(parts) != 3:
        raise SolverError(f"{filename}: VBScript codec tag has an unsupported shape")
    representation, transform, key_text = parts
    text = material.group(1)
    try:
        if representation in {"hex_compact"}:
            encoded = bytes.fromhex(text)
        elif representation == "base64_chunks":
            encoded = base64.b64decode(text, validate=True)
        elif representation == "reversed_hex":
            encoded = bytes.fromhex(text.replace(":", " "))[::-1]
        elif representation == "hex_dash":
            encoded = bytes(int(part, 16) for part in text.split("-"))
        elif representation == "hex_colon":
            encoded = bytes(int(part, 16) for part in text.split(":"))
        elif representation == "decimal_pipe":
            encoded = bytes(int(part, 10) for part in text.split("|"))
        elif representation == "decimal_comma":
            encoded = bytes(int(part, 10) for part in text.split(","))
        elif representation == "decimal_dash":
            encoded = bytes(int(part, 10) for part in text.split("-"))
        elif representation == "reversed_decimal":
            encoded = bytes(int(part, 10) for part in text.split(","))[::-1]
        else:
            raise SolverError(
                f"{filename}: unsupported VBScript material representation {representation!r}"
            )
    except (ValueError, OverflowError) as exc:
        raise SolverError(f"{filename}: VBScript material bytes are malformed") from exc

    key = bytes(int(part, 16) for part in key_text.split(",") if part)
    if transform == "identity":
        decoded = encoded
    elif transform == "single_byte_xor":
        if len(key) != 1:
            raise SolverError(f"{filename}: single-byte XOR key is not one byte")
        decoded = bytes(value ^ key[0] for value in encoded)
    elif transform == "repeating_key_xor":
        if not key:
            raise SolverError(f"{filename}: repeating XOR key is empty")
        decoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
    elif transform == "add_modulo_256":
        if len(key) != 1:
            raise SolverError(f"{filename}: additive transform key is not one byte")
        decoded = bytes((value - key[0]) % 256 for value in encoded)
    elif transform == "subtract_modulo_256":
        if len(key) != 1:
            raise SolverError(f"{filename}: subtractive transform key is not one byte")
        decoded = bytes((value + key[0]) % 256 for value in encoded)
    elif transform == "reverse_bytes":
        decoded = encoded[::-1]
    elif transform == "rolling_xor":
        if len(key) != 1:
            raise SolverError(f"{filename}: rolling XOR seed is not one byte")
        previous = key[0]
        output = bytearray()
        for value in encoded:
            output.append(value ^ previous)
            previous = value
        decoded = bytes(output)
    elif transform == "reverse_then_xor":
        if len(key) != 1:
            raise SolverError(f"{filename}: reverse/XOR key is not one byte")
        decoded = bytes(value ^ key[0] for value in encoded[::-1])
    else:
        raise SolverError(f"{filename}: unsupported VBScript transform {transform!r}")
    return decoded, representation, transform, key_text


def _parse_descriptor_bytes(data: bytes, filename: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{filename}: recovered descriptor is not UTF-8") from exc
    result: dict[str, Any] = {}
    for field in text.split("|"):
        if "=" not in field:
            continue
        key, value = field.split("=", 1)
        result[key] = value
    if result.get("v") != "1" or not isinstance(result.get("steps"), str):
        raise SolverError(f"{filename}: decoded material is not a version 1 descriptor")
    result["steps"] = result["steps"].split(",")
    return result


def _bash_material(source: str, filename: str) -> tuple[bytes, str, str, str]:
    material_match = re.search(
        r"(?im)^\s*readonly\s+Material_[A-Za-z0-9_]+\s*=\s*((?:'[^']*'\s*)+)",
        source,
    )
    codec_match = re.search(
        r"(?im)^\s*readonly\s+Codec_[A-Za-z0-9_]+\s*=\s*'([^']*)'",
        source,
    )
    if material_match is None or codec_match is None:
        raise SolverError(f"{filename}: Bash material/codec constants are missing")
    parts = codec_match.group(1).split("|")
    if len(parts) != 3:
        raise SolverError(f"{filename}: Bash codec tag has an unsupported shape")
    representation, transform, key_text = parts
    encoded_text = "".join(re.findall(r"'([^']*)'", material_match.group(1)))
    try:
        if representation in {"base64_literal", "base64_chunks"}:
            encoded = base64.b64decode(
                re.sub(r"\s+", "", encoded_text), validate=True
            )
        elif representation == "percent_hex":
            encoded = urllib.parse.unquote_to_bytes(encoded_text)
            if re.search(r"%(?![0-9a-fA-F]{2})", encoded_text):
                raise ValueError("malformed percent escape")
        elif representation in {"decimal_space", "decimal_comma", "reversed_decimal"}:
            values = [
                int(value, 10)
                for value in re.findall(r"\d+", encoded_text)
            ]
            if representation == "reversed_decimal":
                values.reverse()
            if any(value > 255 for value in values):
                raise ValueError("decimal byte is outside 0..255")
            encoded = bytes(values)
        elif representation == "hex_compact":
            encoded = bytes.fromhex(encoded_text)
        elif representation in {"hex_colon", "hex_dash"}:
            delimiter = ":" if representation == "hex_colon" else "-"
            encoded = bytes(int(value, 16) for value in encoded_text.split(delimiter))
        else:
            raise SolverError(
                f"{filename}: unsupported Bash material representation {representation!r}"
            )
        key_values = [
            int(value, 16)
            for value in re.findall(r"[0-9a-fA-F]{1,2}", key_text)
        ]
        key = bytes(key_values)
    except (ValueError, OverflowError) as exc:
        raise SolverError(f"{filename}: Bash material bytes are malformed") from exc

    if transform == "identity":
        decoded = encoded
    elif transform == "single_byte_xor":
        if len(key) != 1:
            raise SolverError(f"{filename}: Bash XOR key is not one byte")
        decoded = bytes(value ^ key[0] for value in encoded)
    elif transform == "repeating_key_xor":
        if not key:
            raise SolverError(f"{filename}: Bash repeating XOR key is empty")
        decoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
    elif transform == "add_modulo_256":
        if len(key) != 1:
            raise SolverError(f"{filename}: Bash additive key is not one byte")
        decoded = bytes((value - key[0]) % 256 for value in encoded)
    elif transform == "subtract_modulo_256":
        if len(key) != 1:
            raise SolverError(f"{filename}: Bash subtractive key is not one byte")
        decoded = bytes((value + key[0]) % 256 for value in encoded)
    elif transform == "reverse_bytes":
        decoded = encoded[::-1]
    elif transform == "rolling_xor":
        if len(key) != 1:
            raise SolverError(f"{filename}: Bash rolling XOR seed is not one byte")
        previous = key[0]
        output = bytearray()
        for value in encoded:
            output.append(value ^ previous)
            previous = value
        decoded = bytes(output)
    elif transform == "reverse_then_xor":
        if len(key) != 1:
            raise SolverError(f"{filename}: Bash reverse/XOR key is not one byte")
        decoded = bytes(value ^ key[0] for value in encoded[::-1])
    else:
        raise SolverError(f"{filename}: unsupported Bash transform {transform!r}")
    return decoded, representation, transform, key_text


def _bash_field_value(answer_id: str, descriptor: dict[str, Any]) -> str:
    _, field = parse_answer_id(answer_id)
    prefix = re.match(r"^bash-[a-z]+-", field)
    if not prefix:
        raise SolverError(f"{answer_id}: Bash specimen category was not identified")
    key = field[prefix.end() :]
    role, _ = classify_javascript(descriptor)
    values = {
        "role": role,
        "attack": LANGUAGE_ATTACK.get(role, {}).get("bash"),
        "adapter": descriptor.get("adapter"),
        "campaign": descriptor.get("campaign_id"),
        "host-id": descriptor.get("host_id"),
        "url": descriptor.get("url"),
        "upload-url": descriptor.get("upload_url"),
        "file-path": descriptor.get("file_path"),
        "path": descriptor.get("file_path"),
        "next-stage": descriptor.get("next_stage"),
        "note-name": descriptor.get("note_name"),
        "extension": descriptor.get("extension"),
        "cron-path": descriptor.get("cron_path"),
        "service-name": descriptor.get("service_name"),
        "stage-count": descriptor.get("stage_count"),
        "steps": ">".join(descriptor["steps"]),
    }
    value = values.get(key)
    return "" if value is None else str(value)


def _vbs_control(source: str, filename: str) -> str:
    recovery = re.search(
        r"(?is)\bFunction\s+(Recover_[A-Za-z0-9_]+)\s*\([^)]*\)(.*?)\bEnd\s+Function\b",
        source,
    )
    if recovery is None:
        raise SolverError(f"{filename}: VBScript recovery function was not found")
    body = recovery.group(2)
    decode_call = re.search(r"\bDecode_[A-Za-z0-9_]+\s*\(", body, re.IGNORECASE)
    if decode_call is None:
        raise SolverError(f"{filename}: decode call is missing from recovery function")
    before = body[: decode_call.start()]
    # Select the innermost still-open block surrounding the descriptor decode call.
    events: list[tuple[int, str, bool]] = []
    for match in re.finditer(
        r"(?im)^\s*(Select\s+Case\b|For\b|Do\b|While\b|If\b|End\s+Select\b|Next\b|Loop\b|Wend\b|End\s+If\b)",
        before,
    ):
        token = match.group(1).lower()
        if token.startswith("select"):
            events.append((match.start(), "select_case", True))
        elif token.startswith("for"):
            events.append((match.start(), "for_once", True))
        elif token == "do":
            events.append((match.start(), "do_once", True))
        elif token.startswith("while"):
            events.append((match.start(), "while_once", True))
        elif token.startswith("if"):
            # Single-line conditional assignments do not wrap the decode call.
            line = body[match.start() : body.find("\n", match.start())]
            if re.search(r"\bThen\s*$", line, re.IGNORECASE):
                events.append((match.start(), "if_guard", True))
        elif token == "end select":
            events.append((match.start(), "select_case", False))
        elif token == "next":
            events.append((match.start(), "for_once", False))
        elif token == "loop":
            events.append((match.start(), "do_once", False))
        elif token == "wend":
            events.append((match.start(), "while_once", False))
        elif token == "end if":
            events.append((match.start(), "if_guard", False))
    stack: list[str] = []
    for _, kind, opening in events:
        if opening:
            stack.append(kind)
        elif kind in stack:
            reverse_index = len(stack) - 1 - stack[::-1].index(kind)
            del stack[reverse_index]
    if re.search(r"(?im)^\s*On\s+Error\s+Resume\s+Next\b", before):
        return "error_guard"
    return stack[-1] if stack else "direct"


def _batch_fragments(source: str, filename: str) -> tuple[str, dict[str, Any]]:
    # The inspect path contains the exact split descriptor fragments as inert
    # assignment text. Reassemble them by their numeric suffix, preserving bytes.
    assignments: dict[str, str] = {}
    pattern = (
        r'(?im)^\s*set\s+(?:"((?:fragment|frag|h|item|v_a)\d+)=(.*?)"|'
        r'((?:fragment|frag|h|item|v_a)\d+)=(.*?))\s*(?:&.*)?$'
    )
    for match in re.finditer(pattern, source):
        name = (match.group(1) or match.group(3)).lower()
        value = match.group(2) if match.group(1) else match.group(4)
        # Exclude the assembled output variable, whose right-hand side refers
        # back to the fragments instead of contributing a fragment itself.
        if re.search(r"%(?:fragment|frag|h|item|v_a)\d+%", value, re.IGNORECASE):
            continue
        assignments[name] = value.replace("^|", "|").replace("^&", "&")
    if not assignments:
        raise SolverError(f"{filename}: no static descriptor fragments were found")
    def index_key(item: str) -> tuple[int, str]:
        number = re.search(r"(\d+)$", item)
        return (int(number.group(1)) if number else 0, item)
    joined = "".join(assignments[key] for key in sorted(assignments, key=index_key))
    descriptor = _parse_descriptor_bytes(joined.encode("utf-8"), filename)
    return joined, descriptor


def _batch_reconstruction_lines(source: str) -> list[str]:
    return [
        line
        for line in source.splitlines()
        if re.search(
            r'(?i)\bset\s+"?[A-Za-z_][A-Za-z0-9_]*\s*=.*'
            r'(?:fragment|frag(?:\d|%%)|item\d|h(?:\d|%%)|v_a(?:\d|%%))',
            line,
        )
    ]


def _batch_expansion(source: str, filename: str) -> str:
    lines = _batch_reconstruction_lines(source)
    if not lines:
        raise SolverError(f"{filename}: descriptor reconstruction statement was not found")
    statement = "\n".join(lines)
    for_match = re.search(r"(?i)\bfor\s+%%([A-Za-z])", statement)
    if for_match:
        loop_variable = for_match.group(1)
        indirect_reference = re.search(
            rf"%%(?:fragment|frag|h|v_a)%%{re.escape(loop_variable)}%%",
            statement,
            re.IGNORECASE,
        )
        if indirect_reference:
            return "for_indirect"
    if re.search(r"(?i)\bcall\s+set\b", statement):
        return "call_double"
    if re.search(r"![A-Za-z_][A-Za-z0-9_]*!", statement):
        return "delayed"
    if re.search(r"%[A-Za-z_][A-Za-z0-9_]*%", statement):
        return "percent"
    raise SolverError(f"{filename}: reconstruction expansion form is unclear")


def _batch_control(source: str, filename: str) -> str:
    lines = source.splitlines()
    reconstruction = set(_batch_reconstruction_lines(source))
    statement_indexes = [index for index, line in enumerate(lines) if line in reconstruction]
    if not statement_indexes:
        raise SolverError(f"{filename}: descriptor reconstruction statement was not found")
    statement_index = statement_indexes[0]
    label = None
    for index in range(statement_index - 1, -1, -1):
        match = re.match(r"\s*:([A-Za-z0-9_]+)", lines[index])
        if match:
            label = match.group(1)
            break
    if label:
        caller = re.compile(rf"(?i)\bcall\s+:{re.escape(label)}\b")
        caller_lines = [line for line in lines if caller.search(line)]
        if caller_lines:
            if any(
                re.search(r"(?i)for\s+/l\s+%%\w+\s+in\s+\(1,1,1\).*call\s+:", line)
                for line in caller_lines
            ):
                return "for_once"
            return "call_subroutine"
        # Separator labels are explicitly neutral in the returned rubric; only
        # an actual dispatch label acts as the descriptor's control wrapper.
        if (
            "separator" not in label.casefold()
            and any(
                re.search(rf"(?i)\bgoto\s+:{re.escape(label)}\b", line)
                for line in lines[:statement_index]
            )
        ):
            return "goto_dispatch"
    prior = lines[max(0, statement_index - 3) : statement_index]
    if any(re.search(r"(?i)\bif\s+errorlevel\b", line) for line in prior):
        return "errorlevel_guard"
    if re.match(r"(?i)^\s*if\b", lines[statement_index]):
        return "if_guard"
    if any(
        re.search(r"(?i)^\s*if\b.*(?:\bexit\b|\bgoto\b|\bcall\b|\(\s*$)", line)
        for line in prior
    ):
        return "if_guard"
    return "direct"


def _script_field(answer_id: str, extension: str, descriptor: dict[str, Any]) -> str:
    scope, field = parse_answer_id(answer_id)
    if not field:
        raise SolverError(f"{answer_id}: script category was not identified")
    role, attack = classify_javascript(descriptor)
    if field.endswith("-role"):
        return role
    if field.endswith("-attack"):
        return LANGUAGE_ATTACK.get(role, {}).get(extension, attack)

    values = descriptor.get("values", {})
    if not isinstance(values, dict):
        values = {}
    common = {
        "adapter": descriptor.get("adapter"),
        "campaign": descriptor.get("campaign_id", values.get("campaign_id")),
        "host-id": descriptor.get("host_id", values.get("host_id")),
        "url": descriptor.get("url", values.get("url", values.get("upload_url"))),
        "upload-url": descriptor.get("upload_url", values.get("upload_url")),
        "file-path": descriptor.get("file_path", values.get("file_path")),
        "path": descriptor.get("file_path", values.get("file_path")),
        "name": descriptor.get("note_name", values.get("note_name")),
        "note-name": descriptor.get("note_name", values.get("note_name")),
        "extension": descriptor.get("extension", values.get("extension")),
        "next-stage": descriptor.get("next_stage", values.get("next_stage")),
        "stage": descriptor.get("next_stage", values.get("next_stage")),
        "graph": descriptor.get("graph"),
    }
    suffix = next(
        (
            candidate
            for candidate in (
                "host-id",
                "file-path",
                "upload-url",
                "next-stage",
                "note-name",
            )
            if field.endswith("-" + candidate)
        ),
        field.rsplit("-", 1)[-1],
    )
    value = common.get(suffix)
    return "" if value is None else str(value)


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
        raise SolverError("Cannot map assigned script deliveries to returned question hints")

    ps_cache: dict[str, dict[str, Any]] = {}
    js_cache: dict[str, tuple[dict[str, Any], tuple[str, str, str]]] = {}
    vbs_cache: dict[str, tuple[dict[str, Any], str, str, str, str]] = {}
    batch_cache: dict[str, tuple[dict[str, Any], str, str]] = {}
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}

    for answer_id in answer_ids:
        question = questions[answer_id]
        hint_text = artifact_hint(question)
        if "->" not in hint_text:
            raise SolverError(f"{answer_id}: question has no exact archive member hint")
        archive_hint, member_hint = (
            part.strip().replace("\\", "/") for part in hint_text.rsplit("->", 1)
        )
        archive_name = pathlib.PurePosixPath(archive_hint).name
        scoped = all_members
        if len(artifact_paths) > 1:
            delivery_ref = refs[answer_id]
            if delivery_ref is None:
                raise SolverError(f"{answer_id}: multi-delivery question has no delivery hint")
            scoped = members_by_artifact[ordered_refs.index(delivery_ref)]
        try:
            member_path, member_bytes = unique_by_hint(
                scoped,
                f"{archive_name}/{member_hint}",
                description=f"member for {answer_id}",
            )
        except SolverError:
            member_path, member_bytes = unique_by_hint(
                scoped, member_hint, description=f"member for {answer_id}"
            )

        suffix = pathlib.PurePosixPath(member_path).suffix.lower()
        if suffix == ".ps1":
            if member_path not in ps_cache:
                source = member_bytes.decode("utf-8-sig")
                descriptor, native_types = decode_powershell_descriptor(
                    source, member_path
                )
                ps_cache[member_path] = classify_powershell(descriptor, native_types)
            semantic = answer_semantic(question, answer_id)
            value = ps_cache[member_path].get(semantic, "")
            explanation = (
                f"Statically decoded the assigned PowerShell descriptor and derived "
                f"{semantic} from {member_path}."
            )
        elif suffix == ".js":
            if member_path not in js_cache:
                source = member_bytes.decode("utf-8-sig")
                descriptor = decode_javascript_descriptor(source)
                js_cache[member_path] = (
                    descriptor,
                    _inspect_function_style(source),
                )
            descriptor, style_data = js_cache[member_path]
            value = _jscript_field_value(answer_id, descriptor, style_data)
            explanation = (
                f"Statically decoded the literal JScript recovery payload in "
                f"{member_path}; no script was run."
            )
        elif suffix == ".vbs":
            if member_path not in vbs_cache:
                source = member_bytes.decode("utf-8-sig")
                decoded, representation, transform, key_text = _vbs_material(
                    source, member_path
                )
                descriptor = _parse_descriptor_bytes(decoded, member_path)
                control = _vbs_control(source, member_path)
                vbs_cache[member_path] = (
                    descriptor,
                    representation,
                    transform,
                    key_text,
                    control,
                )
            descriptor, representation, transform, key_text, control = vbs_cache[
                member_path
            ]
            if answer_id.endswith("-representation"):
                value = representation
            elif answer_id.endswith("-transform"):
                value = transform
            elif answer_id.endswith("-control"):
                value = control
            else:
                value = _script_field(answer_id, suffix[1:], descriptor)
            explanation = (
                f"Parsed the VBScript material and codec constants, applied the "
                f"declared {representation}|{transform}|{key_text} representation, "
                f"and recovered the descriptor statically from {member_path}."
            )
        elif suffix in {".cmd", ".bat"}:
            if member_path not in batch_cache:
                source = member_bytes.decode("utf-8-sig")
                _, descriptor = _batch_fragments(source, member_path)
                expansion = _batch_expansion(source, member_path)
                control = _batch_control(source, member_path)
                batch_cache[member_path] = descriptor, expansion, control
            descriptor, expansion, control = batch_cache[member_path]
            if answer_id.endswith("-expansion"):
                value = expansion
            elif answer_id.endswith("-control"):
                value = control
            else:
                value = _script_field(answer_id, suffix[1:], descriptor)
            explanation = (
                f"Reassembled the static batch descriptor fragments in {member_path}, "
                f"read the reconstruction expansion/control syntax ({expansion}, "
                f"{control}), and classified the recovered graph without running it."
            )
        elif suffix == ".sh":
            if member_path not in batch_cache:
                decoded, representation, transform, key_text = _bash_material(
                    member_bytes.decode("utf-8-sig"), member_path
                )
                descriptor = _parse_descriptor_bytes(decoded, member_path)
                batch_cache[member_path] = (
                    descriptor,
                    representation,
                    transform + "|" + key_text,
                )
            descriptor, representation, transform_key = batch_cache[member_path]
            value = _bash_field_value(answer_id, descriptor)
            explanation = (
                f"Decoded the literal Bash material using {representation} and "
                f"{transform_key}, parsed the recovered descriptor and ordered "
                f"steps, and derived the requested field from {member_path}; "
                "the script was not run."
            )
        else:
            raise SolverError(f"{answer_id}: unsupported hinted script type {suffix!r}")

        if not value:
            raise SolverError(f"{answer_id}: the assigned bytes do not determine this field")
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = explanation

    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically analyze Shell Contrast script specimens")


if __name__ == "__main__":
    main()
