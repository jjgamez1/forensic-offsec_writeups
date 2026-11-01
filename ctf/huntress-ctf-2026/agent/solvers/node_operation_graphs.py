#!/usr/bin/env python3
"""Recover static descriptors across the Day 7 multilingual graph bundle."""

from __future__ import annotations

import base64
import ast
import codecs
import json
import pathlib
import re
import urllib.parse
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)
from agent.solvers.host_with_the_most import classify_javascript, collect_members
from agent.solvers import python_carrier_lab
from agent.solvers.shell_contrast import (
    _bash_material,
    _parse_descriptor_bytes,
    _script_field,
    _vbs_control,
    _vbs_material,
    solve_detailed as solve_shell,
)


NODE_ATTACK = {
    "benign": "none",
    "acquire": "T1105",
    "embedded": "T1140",
    "upload": "T1041",
    "process": "T1059.007",
    "schedule": "T1053.005",
    "impact": "T1486",
    "script": "T1059.007",
}


def _node_descriptor(source: str, label: str) -> dict[str, Any]:
    material_match = re.search(
        r'(?im)^\s*const\s+Material_[A-Za-z0-9_]+\s*=\s*"((?:\\.|[^"])*)"\s*;',
        source,
    )
    codec_match = re.search(
        r'(?im)^\s*const\s+Codec_[A-Za-z0-9_]+\s*=\s*"([^"]*)"\s*;',
        source,
    )
    if material_match is None or codec_match is None:
        raise SolverError(f"{label}: Node.js material or codec constant is missing")
    try:
        material = ast.literal_eval('"' + material_match.group(1) + '"')
    except (SyntaxError, ValueError) as exc:
        raise SolverError(f"{label}: Node.js string material is malformed") from exc
    codec = codec_match.group(1).split("|")
    if len(codec) != 3:
        raise SolverError(f"{label}: Node.js codec tag has an unsupported shape")
    representation, transform, key_text = codec
    try:
        if representation in {"base64_literal", "base64_chunks"}:
            encoded = base64.b64decode(material, validate=True)
        elif representation in {"json_numbers", "decimal_array"}:
            values = json.loads(material)
            if not isinstance(values, list) or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > 255
                for value in values
            ):
                raise ValueError("JSON byte array contains a non-byte value")
            encoded = bytes(values)
        elif representation == "reversed_decimal":
            tokens = material.split(",")
            if not tokens or any(not token.isdecimal() for token in tokens):
                raise ValueError("reversed decimal byte array is malformed")
            values = [int(token) for token in tokens]
            if any(value > 255 for value in values):
                raise ValueError("reversed decimal byte array contains a non-byte")
            encoded = bytes(reversed(values))
        elif representation == "percent_hex":
            if re.search(r"%(?![0-9a-fA-F]{2})", material):
                raise ValueError("malformed percent escape")
            encoded = urllib.parse.unquote_to_bytes(material)
        elif representation == "unicode_escapes":
            values = re.findall(r"\\u([0-9a-fA-F]{4})", material)
            residue = re.sub(r"\\u[0-9a-fA-F]{4}", "", material)
            if not values or residue or any(int(value, 16) > 0xFF for value in values):
                raise ValueError("Unicode escape material is not a byte sequence")
            encoded = bytes(int(value, 16) for value in values)
        elif representation == "hex_buffer":
            encoded = bytes.fromhex(material)
        elif representation == "hex_array":
            values = json.loads(material)
            encoded = bytes(int(value, 16) for value in values)
        elif representation == "escaped_octets":
            token_pattern = r"(?:\\){1,2}x([0-9a-fA-F]{2})"
            octets = re.findall(token_pattern, material)
            residue = re.sub(r"(?:\\){1,2}x[0-9a-fA-F]{2}", "", material)
            if not octets or residue:
                raise ValueError("escaped octet string contains non-octet data")
            encoded = bytes(int(value, 16) for value in octets)
        else:
            raise SolverError(
                f"{label}: unsupported Node.js representation {representation!r}"
            )
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SolverError(f"{label}: Node.js material bytes are malformed") from exc

    key_values = [int(part, 16) for part in key_text.split(",") if part]
    key = key_values[0] if key_values else 0
    if transform == "identity":
        decoded = encoded
    elif transform == "reverse_bytes":
        decoded = encoded[::-1]
    elif transform == "single_byte_xor":
        if len(key_values) != 1:
            raise SolverError(f"{label}: single-byte XOR key is malformed")
        decoded = bytes(value ^ key for value in encoded)
    elif transform == "repeating_key_xor":
        if not key_values:
            raise SolverError(f"{label}: repeating XOR key is empty")
        decoded = bytes(
            value ^ key_values[index % len(key_values)]
            for index, value in enumerate(encoded)
        )
    elif transform == "add_modulo_256":
        decoded = bytes((value - key) % 256 for value in encoded)
    elif transform == "subtract_modulo_256":
        decoded = bytes((value + key) % 256 for value in encoded)
    elif transform == "rolling_xor":
        previous = key
        output = bytearray()
        for value in encoded:
            output.append(value ^ previous)
            previous = value
        decoded = bytes(output)
    elif transform == "reverse_then_xor":
        if len(key_values) != 1:
            raise SolverError(f"{label}: reverse/XOR key is malformed")
        decoded = bytes(value ^ key_values[0] for value in encoded[::-1])
    else:
        raise SolverError(f"{label}: unsupported Node.js transform {transform!r}")
    return _parse_descriptor_bytes(decoded, label)


def _node_role(steps: list[str]) -> str:
    if steps[-2:] == ["decode_configuration", "return_configuration"]:
        return "benign_utility"
    if steps[-3:] == [
        "decode_configuration",
        "locate_interpreter",
        "dispatch_next_stage",
    ]:
        return "relay"
    if steps[-1:] == ["dispatch_next_stage"] or steps[-1:] == ["handoff_script"]:
        return "staged_chain"
    if steps[-2:] == ["build_schedule", "register_descriptor"]:
        return "persistence_descriptor"
    if steps[-2:] == ["transform_content", "write_recovery_note"] or steps[-2:] == [
        "transform_copy",
        "write_recovery_note",
    ]:
        return "impact"
    if steps[-1:] in (["upload_remote"], ["transmit_remote"]):
        return "uploader"
    if steps[-2:] == ["locate_local", "dispatch_process"]:
        return "launcher"
    if steps[-2:] == ["decode_embedded", "write_file"]:
        return "dropper"
    if steps[-2:] == ["acquire_remote", "write_file"]:
        return "downloader"
    if "acquire_remote" in steps and steps[-1:] in (
        ["dispatch_memory"],
        ["dispatch_pipe"],
        ["dispatch_process"],
    ):
        return "stager"
    raise SolverError(f"Unclassified Node.js ordered graph: {steps!r}")


def _node_attack(steps: list[str]) -> str:
    if steps[-1:] in (["handoff_script"], ["dispatch_next_stage"]):
        return NODE_ATTACK["script"]
    if steps[-2:] == ["decode_configuration", "return_configuration"]:
        return NODE_ATTACK["benign"]
    if "acquire_remote" in steps:
        return NODE_ATTACK["acquire"]
    if "decode_embedded" in steps:
        return NODE_ATTACK["embedded"]
    if steps[-1:] in (["upload_remote"], ["transmit_remote"]):
        return NODE_ATTACK["upload"]
    if "dispatch_process" in steps:
        return NODE_ATTACK["process"]
    if steps[-2:] == ["build_schedule", "register_descriptor"]:
        return NODE_ATTACK["schedule"]
    if steps[-2:] in (
        ["transform_content", "write_recovery_note"],
        ["transform_copy", "write_recovery_note"],
    ):
        return NODE_ATTACK["impact"]
    raise SolverError(f"Unclassified Node.js attack graph: {steps!r}")


def _suffix_value(answer_id: str, descriptor: dict[str, Any]) -> str:
    _, field = parse_answer_id(answer_id)
    match = re.match(r"^nodejs-[a-z]+-(.+)$", field)
    if match is None:
        raise SolverError(f"{answer_id}: Node.js specimen or field is malformed")
    suffix = match.group(1)
    steps = descriptor.get("steps")
    if not isinstance(steps, list) or not all(isinstance(x, str) for x in steps):
        raise SolverError(f"{answer_id}: decoded Node.js steps are malformed")
    if suffix == "role":
        return _node_role(steps)
    if suffix == "attack":
        return _node_attack(steps)
    values = {
        "adapter": descriptor.get("adapter"),
        "campaign": descriptor.get("campaign_id"),
        "id": descriptor.get("campaign_id"),
        "host-id": descriptor.get("host_id"),
        "url": descriptor.get("url"),
        "file-path": descriptor.get("file_path"),
        "schedule-path": descriptor.get("schedule_path"),
        "service-name": descriptor.get("service_name"),
        "stage-count": descriptor.get("stage_count"),
        "steps": ">".join(steps),
    }
    value = values.get(suffix)
    if value is None:
        raise SolverError(f"{answer_id}: decoded descriptor has no {suffix!r} field")
    return str(value)


def _bash_value(answer_id: str, descriptor: dict[str, Any]) -> str:
    _, field = parse_answer_id(answer_id)
    match = re.match(r"^bash-.+-(role|attack|adapter|campaign|host-id|url|upload-url|file-path|path|next-stage|note-name|extension|cron-path|service-name|stage-count|steps|feature|primitive)$", field)
    if match is None:
        raise SolverError(f"{answer_id}: Bash field is not recognized")
    suffix = match.group(1)
    steps = descriptor.get("steps")
    if not isinstance(steps, list):
        raise SolverError(f"{answer_id}: decoded Bash steps are malformed")
    if suffix == "role":
        if descriptor.get("feature") is not None:
            return "advanced_syntax"
        role, _ = classify_javascript(descriptor)
        return role
    if suffix == "attack":
        if descriptor.get("feature") is not None:
            return "T1059.004"
        from agent.solvers.shell_contrast import LANGUAGE_ATTACK

        role, attack = classify_javascript(descriptor)
        return LANGUAGE_ATTACK.get(role, {}).get("bash", attack)
    values = {
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
        "steps": ">".join(steps),
        "feature": descriptor.get("feature"),
        "primitive": descriptor.get("primitive"),
    }
    value = values.get(suffix)
    if value is None:
        raise SolverError(f"{answer_id}: decoded Bash descriptor has no {suffix!r}")
    return str(value)


def _bash_material_extended(source: str, label: str) -> tuple[bytes, str, str, str]:
    try:
        return _bash_material(source, label)
    except SolverError as exc:
        if "Bash codec tag has an unsupported shape" in str(exc):
            material = re.search(
                r"(?im)^\s*readonly\s+Material_[A-Za-z0-9_]+\s*=\s*'([^']*)'",
                source,
            )
            codec = re.search(
                r"(?im)^\s*readonly\s+Codec_[A-Za-z0-9_]+\s*=\s*'([^']*)'",
                source,
            )
            simple_representation = (
                codec.group(1).removesuffix("|")
                if codec is not None and codec.group(1).endswith("|")
                else None
            )
            if material is not None and simple_representation in {
                "base64_literal",
                "hex_compact",
                "decimal_csv",
                "percent_hex",
                "reversed_base64",
            }:
                try:
                    text = material.group(1)
                    if simple_representation == "base64_literal":
                        data = base64.b64decode(text, validate=True)
                    elif simple_representation == "reversed_base64":
                        data = base64.b64decode(text[::-1], validate=True)
                    elif simple_representation == "hex_compact":
                        data = bytes.fromhex(text)
                    elif simple_representation == "percent_hex":
                        if re.search(r"%(?![0-9a-fA-F]{2})", text):
                            raise ValueError("malformed percent escape")
                        data = urllib.parse.unquote_to_bytes(text)
                    else:
                        values = text.split(",")
                        if not values or any(not re.fullmatch(r"\d{1,3}", item) for item in values):
                            raise ValueError("decimal CSV is malformed")
                        octets = [int(item, 10) for item in values]
                        if any(value > 255 for value in octets):
                            raise ValueError("decimal CSV byte is outside 0..255")
                        data = bytes(octets)
                    return data, simple_representation, "identity", ""
                except (ValueError, base64.binascii.Error) as decode_error:
                    raise SolverError(
                        f"{label}: advanced Bash material is malformed"
                    ) from decode_error
            if material is not None and codec is not None:
                codec_parts = codec.group(1).split("|")
                if len(codec_parts) == 2 and codec_parts[0] == "xor_hex":
                    try:
                        encoded = bytes.fromhex(material.group(1))
                        if not re.fullmatch(r"[0-9a-fA-F]{1,2}", codec_parts[1]):
                            raise ValueError("XOR key is not one byte")
                        key = int(codec_parts[1], 16)
                        data = bytes(value ^ key for value in encoded)
                    except ValueError as decode_error:
                        raise SolverError(
                            f"{label}: advanced Bash XOR/hex material is malformed"
                        ) from decode_error
                    return data, "xor_hex", "single_byte_xor", codec_parts[1]
        if "unsupported Bash material representation 'decimal_colon'" not in str(exc):
            raise
    codec = re.search(
        r"(?im)^(\s*readonly\s+Codec_[A-Za-z0-9_]+\s*=\s*)'decimal_colon(\|[^']*)'",
        source,
    )
    if codec is None:
        raise SolverError(f"{label}: decimal-colon Bash codec declaration is missing")
    normalized = (
        source[: codec.start()]
        + codec.group(1)
        + "'decimal_comma"
        + codec.group(2)
        + "'"
        + source[codec.end() :]
    )
    material = re.search(
        r"(?im)^(\s*readonly\s+Material_[A-Za-z0-9_]+\s*=\s*)'([^']*)'",
        normalized,
    )
    if material is None:
        raise SolverError(f"{label}: decimal-colon Bash material declaration is missing")
    raw = material.group(2)
    tokens = raw.split(":")
    if not tokens or any(not re.fullmatch(r"\d+", token) for token in tokens):
        raise SolverError(f"{label}: decimal-colon Bash bytes are malformed")
    values = [int(token, 10) for token in tokens]
    if any(value > 255 for value in values):
        raise SolverError(f"{label}: decimal-colon Bash byte is outside 0..255")
    comma_text = ",".join(tokens)
    normalized = (
        normalized[: material.start()]
        + material.group(1)
        + "'"
        + comma_text
        + "'"
        + normalized[material.end() :]
    )
    decoded, _, transform, key = _bash_material(normalized, label)
    return decoded, "decimal_colon", transform, key


def _vbs_material_extended(
    source: str, label: str
) -> tuple[bytes, str, str, str]:
    material_match = re.search(
        r'(?im)^\s*Const\s+Material_[A-Za-z0-9_]+\s*=\s*"([^"]*)"',
        source,
    )
    codec_match = re.search(
        r'(?im)^\s*Const\s+Codec_[A-Za-z0-9_]+\s*=\s*"([^"]*)"',
        source,
    )
    if material_match is None or codec_match is None:
        raise SolverError(f"{label}: VBScript material/codec constants are missing")
    representation, transform, key_text = codec_match.group(1).split("|")
    if representation != "base64_literal":
        return _vbs_material(source, label)
    try:
        encoded = base64.b64decode(material_match.group(1), validate=True)
        key = bytes(int(part, 16) for part in key_text.split(",") if part)
    except (ValueError, base64.binascii.Error) as exc:
        raise SolverError(f"{label}: VBScript Base64 material is malformed") from exc
    if transform == "identity":
        decoded = encoded
    elif transform == "single_byte_xor" and len(key) == 1:
        decoded = bytes(value ^ key[0] for value in encoded)
    elif transform == "repeating_key_xor" and key:
        decoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
    elif transform == "add_modulo_256" and len(key) == 1:
        decoded = bytes((value - key[0]) % 256 for value in encoded)
    elif transform == "subtract_modulo_256" and len(key) == 1:
        decoded = bytes((value + key[0]) % 256 for value in encoded)
    elif transform == "reverse_bytes":
        decoded = encoded[::-1]
    elif transform == "rolling_xor" and len(key) == 1:
        previous = key[0]
        output = bytearray()
        for value in encoded:
            output.append(value ^ previous)
            previous = value
        decoded = bytes(output)
    elif transform == "reverse_then_xor" and len(key) == 1:
        decoded = bytes(value ^ key[0] for value in encoded[::-1])
    else:
        raise SolverError(f"{label}: unsupported VBScript transform {transform!r}")
    return decoded, representation, transform, key_text


def _python_config_with_hex_literal(source: str, label: str) -> dict[str, str]:
    try:
        fields, _ = python_carrier_lab._decode_config(source, label)
        return fields
    except SolverError as exc:
        if "unsupported material representation 'hex_literal'" not in str(exc):
            raise
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as exc:
        raise SolverError(f"{label}: Python source has invalid syntax") from exc
    assignments = python_carrier_lab._fixture_assignments(tree)
    material_items = [
        (name, value)
        for name, value in assignments.items()
        if name.startswith("MATERIAL_")
    ]
    codec_items = [
        (name, value)
        for name, value in assignments.items()
        if name.startswith("CODEC_")
    ]
    if (
        len(material_items) != 1
        or len(codec_items) != 1
        or not isinstance(material_items[0][1], str)
        or not isinstance(codec_items[0][1], str)
    ):
        raise SolverError(f"{label}: expected one literal Python material and codec")
    material_name, material = material_items[0]
    codec_name, codec = codec_items[0]
    parts = codec.split("|")
    if len(parts) != 3 or parts[0] != "hex_literal":
        raise SolverError(f"{label}: unsupported Python codec shape")
    if len(material) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", material):
        raise SolverError(f"{label}: compact hexadecimal material is malformed")
    colon_hex = ":".join(material[index : index + 2] for index in range(0, len(material), 2))
    normalized = re.sub(
        rf"(?m)^(\s*{re.escape(material_name)}\s*=\s*)[\"'][^\"']*[\"']",
        lambda match: f'{match.group(1)}"{colon_hex}"',
        source,
    )
    normalized = re.sub(
        rf"(?m)^(\s*{re.escape(codec_name)}\s*=\s*)[\"'][^\"']*[\"']",
        lambda match: f'{match.group(1)}"{ "|".join(["hex_colon", *parts[1:]]) }"',
        normalized,
    )
    fields, _ = python_carrier_lab._decode_config(normalized, label)
    return fields


def _solve_python_extended(
    ids: list[str],
    questions: dict[str, dict[str, Any]],
    artifact_paths: list[pathlib.Path],
) -> tuple[dict[str, str], dict[str, str]]:
    _, members_by_artifact = collect_members(artifact_paths)
    ordered_delivery_refs = list(range(len(members_by_artifact)))
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    cache: dict[str, dict[str, str]] = {}
    for answer_id in ids:
        question = questions[answer_id]
        hint = artifact_hint(question)
        delivery_match = re.search(r"\bdelivery\s+(\d+)\b", hint, re.I)
        if len(members_by_artifact) > 1:
            if delivery_match is None:
                raise SolverError(f"{answer_id}: Python delivery hint is missing")
            delivery_index = int(delivery_match.group(1)) - 1
            if delivery_index not in ordered_delivery_refs:
                raise SolverError(f"{answer_id}: Python delivery index is invalid")
            scoped = members_by_artifact[delivery_index]
        else:
            scoped = members_by_artifact[0]
        member_hint = hint.rsplit("->", 1)[-1].strip()
        member_label, source_bytes = unique_by_hint(
            scoped, member_hint, description=f"Python carrier for {answer_id}"
        )
        if member_label not in cache:
            try:
                source = source_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise SolverError(f"{member_label}: source is not UTF-8") from exc
            cache[member_label] = _python_config_with_hex_literal(source, member_label)
        value = python_carrier_lab._python_field_value(
            answer_id, cache[member_label], member_label
        )
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {member_label} using the question's member hint, verified "
            "the literal codec and decoder statically, and derived the answer "
            "from the decoded descriptor."
        )
    return answers, reasoning


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    split = {
        "nodejs": [],
        "bash": [],
        "python": [],
        "vbscript": [],
        "shell": [],
    }
    for answer_id in answer_ids:
        field = parse_answer_id(answer_id)[1]
        prefix = field.split("-", 1)[0]
        split[
            prefix
            if prefix in {"nodejs", "bash", "python", "vbscript"}
            else "shell"
        ].append(answer_id)

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}

    def solve_subset(ids: list[str], solver) -> None:
        if not ids:
            return
        subset = dict(start)
        subset["answer_ids"] = ids
        subset["questions"] = [questions[answer_id] for answer_id in ids]
        subset_answers, subset_reasoning, _ = solver(subset, artifact_paths)
        answers.update(subset_answers)
        reasoning.update(subset_reasoning)

    solve_subset(split["shell"], solve_shell)
    if split["python"]:
        python_start = dict(start)
        python_start["answer_ids"] = split["python"]
        python_start["questions"] = [questions[item] for item in split["python"]]
        try:
            py_answers, py_reasoning, _ = python_carrier_lab.solve_detailed(
                python_start, artifact_paths
            )
        except SolverError as exc:
            if "unsupported material representation 'hex_literal'" not in str(exc):
                raise
            py_answers, py_reasoning = _solve_python_extended(
                split["python"], questions, artifact_paths
            )
        answers.update(py_answers)
        reasoning.update(py_reasoning)

    solve_vbscript = split["vbscript"]
    members, _ = collect_members(artifact_paths)
    cache: dict[str, dict[str, Any]] = {}
    vbs_cache: dict[str, tuple[dict[str, Any], str, str, str, str]] = {}
    for answer_id in split["nodejs"] + split["bash"] + solve_vbscript:
        question = questions[answer_id]
        hint = artifact_hint(question)
        if "->" not in hint:
            raise SolverError(f"{answer_id}: question has no exact member hint")
        _, member_hint = (
            part.strip().replace("\\", "/") for part in hint.rsplit("->", 1)
        )
        member_label, data = unique_by_hint(
            members, member_hint, description=f"script member for {answer_id}"
        )
        if member_label not in cache:
            source = data.decode("utf-8-sig")
            if member_label.lower().endswith(".mjs"):
                cache[member_label] = _node_descriptor(source, member_label)
            elif member_label.lower().endswith(".sh"):
                decoded, _, _, _ = _bash_material_extended(source, member_label)
                cache[member_label] = _parse_descriptor_bytes(decoded, member_label)
            elif member_label.lower().endswith(".vbs"):
                decoded, representation, transform, key_text = (
                    _vbs_material_extended(source, member_label)
                )
                descriptor = _parse_descriptor_bytes(decoded, member_label)
                control = _vbs_control(source, member_label)
                if control == "if_guard":
                    control = "error_guard"
                vbs_cache[member_label] = (
                    descriptor,
                    representation,
                    transform,
                    key_text,
                    control,
                )
            else:
                raise SolverError(f"{member_label}: unsupported hinted Node/Bash member")
        if answer_id in split["nodejs"]:
            value = _suffix_value(answer_id, cache[member_label])
        elif answer_id in split["bash"]:
            value = _bash_value(answer_id, cache[member_label])
        else:
            descriptor, representation, transform, key_text, control = vbs_cache[
                member_label
            ]
            if answer_id.endswith("-representation"):
                value = representation
            elif answer_id.endswith("-transform"):
                value = transform
            elif answer_id.endswith("-control"):
                value = control
            else:
                value = _script_field(answer_id, ".vbs", descriptor)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Decoded the static {member_label} material and derived the "
            "requested field from its ordered behavior graph; no script ran."
        )

    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Decode the Day 7 Node.js operation graph bundle")


if __name__ == "__main__":
    main()
