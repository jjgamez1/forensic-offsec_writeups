#!/usr/bin/env python3
"""Statically decode Python carrier fixtures and reuse the shell analyzers."""

from __future__ import annotations

import ast
import base64
import pathlib
import re
from typing import Any

from agent.answer_ids import parse_answer_id
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
from agent.solvers.host_with_the_most import collect_members
from agent.solvers import shell_contrast


PYTHON_FIELDS = (
    "windows-chain",
    "next-stage",
    "handoff-id",
    "host-id",
    "file-path",
    "upload-url",
    "user-agent",
    "extension",
    "campaign",
    "adapter",
    "syntax",
    "obfuscation",
    "carrier",
    "role",
    "attack",
    "url",
)
ROLE_VALUES = {
    "benign_utility",
    "stager",
    "dropper",
    "downloader",
    "uploader",
    "launcher",
    "impact",
    "staged_chain",
    "relay",
    "persistence_descriptor",
}
ATTACK_BY_STEP = {
    "acquire_remote": "T1105",
    "decode_embedded": "T1140",
    "transmit_remote": "T1041",
    "upload_remote": "T1041",
    "dispatch_process": "T1059.006",
    "register_descriptor": "T1053.005",
    "write_recovery_note": "T1486",
}


def _fixture_assignments(tree: ast.AST) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value_node = node.value
        if value_node is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if not target.id.startswith(("MATERIAL_", "CODEC_")):
                continue
            try:
                values[target.id] = ast.literal_eval(value_node)
            except (ValueError, TypeError, SyntaxError) as exc:
                raise SolverError(
                    f"{target.id}: carrier constant is not a literal value"
                ) from exc
    return values


def _named_functions(tree: ast.AST, prefix: str) -> list[ast.FunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name.startswith(prefix)
    ]


def _contains_operator(node: ast.AST, operator: type[ast.operator]) -> bool:
    return any(isinstance(child, ast.BinOp) and isinstance(child.op, operator) for child in ast.walk(node))


def _contains_call(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(child, ast.Call)
        and (
            (isinstance(child.func, ast.Name) and child.func.id == name)
            or (isinstance(child.func, ast.Attribute) and child.func.attr == name)
        )
        for child in ast.walk(node)
    )


def _verify_decoder(tree: ast.AST, transform: str, key: bytes) -> None:
    functions = _named_functions(tree, "decode_")
    if len(functions) != 1:
        raise SolverError("Expected one statically identifiable Python decode function")
    decoder = functions[0]
    has_reverse = _contains_call(decoder, "reversed")
    if transform in {"reverse_bytes", "reverse_then_xor"} and not has_reverse:
        raise SolverError("Codec declares byte reversal absent from its decode function")
    if transform not in {"reverse_bytes", "reverse_then_xor"} and has_reverse:
        raise SolverError("Decode function reverses bytes contrary to its codec declaration")

    if transform in {
        "reverse_then_xor",
        "single_byte_xor",
        "repeating_key_xor",
        "rolling_xor",
    }:
        if not _contains_operator(decoder, ast.BitXor):
            raise SolverError("Codec declares XOR absent from its decode function")
        constants = {
            child.value
            for child in ast.walk(decoder)
            if isinstance(child, ast.Constant) and isinstance(child.value, int)
        }
        if not key or not set(key).issubset(constants):
            raise SolverError("Codec XOR key does not match the decode function")
        if transform == "repeating_key_xor" and not _contains_operator(
            decoder, ast.Mod
        ):
            raise SolverError("Codec repeating XOR does not cycle through its key")
        if transform in {"reverse_then_xor", "single_byte_xor", "rolling_xor"} and len(key) != 1:
            raise SolverError(f"Codec {transform} requires a one-byte key")
        if transform == "rolling_xor":
            carries_previous_byte = any(
                isinstance(child, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and isinstance(child.value, ast.Name)
                    and child.value.id in {"value", "item", "byte"}
                    for target in child.targets
                )
                for child in ast.walk(decoder)
            )
            if not carries_previous_byte:
                raise SolverError(
                    "Codec rolling XOR does not update its key from the prior encoded byte"
                )
    elif transform == "add_modulo_256":
        if not _contains_operator(decoder, ast.Sub) or not _contains_operator(decoder, ast.Mod):
            raise SolverError("Codec add transform does not match the decode function")
        constants = {
            child.value
            for child in ast.walk(decoder)
            if isinstance(child, ast.Constant) and isinstance(child.value, int)
        }
        if len(key) != 1 or key[0] not in constants:
            raise SolverError("Codec add key does not match the decode function")
    elif transform == "subtract_modulo_256":
        if not _contains_operator(decoder, ast.Add) or not _contains_operator(decoder, ast.Mod):
            raise SolverError("Codec subtract transform does not match the decode function")
        constants = {
            child.value
            for child in ast.walk(decoder)
            if isinstance(child, ast.Constant) and isinstance(child.value, int)
        }
        if len(key) != 1 or key[0] not in constants:
            raise SolverError("Codec subtract key does not match the decode function")
    elif transform not in {"identity", "reverse_bytes"}:
        raise SolverError(f"Unsupported Python byte transform {transform!r}")


def _decode_config(source: str, filename: str) -> tuple[dict[str, str], ast.AST]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise SolverError(f"{filename}: recovered Python source has invalid syntax") from exc
    assignments = _fixture_assignments(tree)
    materials = [value for key, value in assignments.items() if key.startswith("MATERIAL_")]
    codecs = [value for key, value in assignments.items() if key.startswith("CODEC_")]
    if len(materials) != 1 or len(codecs) != 1 or not isinstance(codecs[0], str):
        raise SolverError(f"{filename}: expected one literal material and codec declaration")
    material, codec = materials[0], codecs[0]
    codec_parts = codec.split("|")
    if len(codec_parts) != 3:
        raise SolverError(f"{filename}: codec declaration has an unsupported shape")
    representation, transform, key_text = codec_parts
    try:
        key = (
            bytes(int(value, 16) for value in key_text.split(",") if value)
            if key_text
            else b""
        )
    except ValueError as exc:
        raise SolverError(f"{filename}: codec key is not hexadecimal") from exc
    _verify_decoder(tree, transform, key)

    try:
        if representation == "decimal_csv" and isinstance(material, str):
            encoded = bytes(int(value, 10) for value in material.split(","))
        elif representation == "hex_escape" and isinstance(material, bytes):
            encoded = material
        elif representation == "integer_list" and isinstance(material, list):
            encoded = bytes(material)
        elif representation == "integer_tuple" and isinstance(material, tuple):
            encoded = bytes(material)
        elif representation == "reversed_integer_list" and isinstance(material, list):
            encoded = bytes(reversed(material))
        elif representation in {"base64_chunks", "base64_literal"} and isinstance(material, str):
            encoded = base64.b64decode(material, validate=True)
        elif representation == "urlsafe_base64" and isinstance(material, str):
            encoded = base64.urlsafe_b64decode(material)
        elif representation == "hex_colon" and isinstance(material, str):
            encoded = bytes.fromhex(material.replace(":", " "))
        else:
            raise SolverError(
                f"{filename}: unsupported material representation {representation!r}"
            )
    except (ValueError, TypeError, OverflowError) as exc:
        raise SolverError(f"{filename}: encoded configuration bytes are malformed") from exc

    if transform == "identity":
        decoded = encoded
    elif transform == "reverse_bytes":
        decoded = encoded[::-1]
    elif transform == "reverse_then_xor":
        decoded = bytes(value ^ key[0] for value in reversed(encoded))
    elif transform == "single_byte_xor":
        decoded = bytes(value ^ key[0] for value in encoded)
    elif transform == "repeating_key_xor":
        decoded = bytes(
            value ^ key[index % len(key)] for index, value in enumerate(encoded)
        )
    elif transform == "add_modulo_256":
        decoded = bytes((value - key[0]) % 256 for value in encoded)
    elif transform == "subtract_modulo_256":
        decoded = bytes((value + key[0]) % 256 for value in encoded)
    elif transform == "rolling_xor":
        previous = key[0]
        output = bytearray()
        for value in encoded:
            output.append(value ^ previous)
            previous = value
        decoded = bytes(output)
    else:
        raise SolverError(f"{filename}: unsupported transform {transform!r}")

    try:
        text = decoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{filename}: decoded configuration is not ASCII") from exc
    fields: dict[str, str] = {}
    for item in text.split("|"):
        if "=" not in item:
            raise SolverError(f"{filename}: decoded configuration field lacks '='")
        name, value = item.split("=", 1)
        if not name or name in fields:
            raise SolverError(f"{filename}: decoded configuration has an invalid key")
        fields[name] = value
    if fields.get("v") != "2" or "steps" not in fields:
        raise SolverError(f"{filename}: unsupported configuration version or missing steps")
    return fields, tree


def _role_and_attack(fields: dict[str, str], filename: str) -> tuple[str, str]:
    steps = [step for step in fields.get("steps", "").split(",") if step]
    if not steps:
        raise SolverError(f"{filename}: decoded behavior graph has no steps")
    step_set = set(steps)
    terminal = steps[-1]

    if steps[0] == "decode_configuration" and terminal == "return_configuration":
        role = "benign_utility"
    elif "build_schedule" in step_set and "register_descriptor" in step_set:
        role = "persistence_descriptor"
    elif (
        step_set.intersection({"transform_content", "transform_copy"})
        and "write_recovery_note" in step_set
    ):
        role = "impact"
    elif terminal in {"dispatch_next_stage", "handoff_script"}:
        role = (
            "relay"
            if "decode_configuration" in step_set and "locate_interpreter" in step_set
            else "staged_chain"
        )
    elif terminal in {"transmit_remote", "upload_remote"}:
        role = "uploader"
    elif terminal == "dispatch_process":
        if "locate_local" in step_set and "acquire_remote" not in step_set:
            role = "launcher"
        elif "acquire_remote" in step_set or "decode_embedded" in step_set:
            role = "staged_chain"
        else:
            raise SolverError(f"{filename}: dispatch_process graph has no defined role")
    elif "acquire_remote" in step_set and "dispatch_memory" in step_set:
        role = "stager"
    elif "acquire_remote" in step_set and "write_file" in step_set:
        role = "downloader"
    elif "decode_embedded" in step_set and "write_file" in step_set:
        role = "dropper"
    else:
        raise SolverError(f"{filename}: behavior graph does not match a defined role")

    if role in {"staged_chain", "relay"}:
        attack = "T1059.006"
    elif role == "benign_utility":
        attack = "none"
    else:
        attack = next(
            (ATTACK_BY_STEP[step] for step in steps if step in ATTACK_BY_STEP),
            "",
        )
    if role not in ROLE_VALUES or not attack:
        raise SolverError(f"{filename}: role or ATT&CK mapping is unsupported")
    return role, attack


def _python_field_value(
    answer_id: str, fields: dict[str, str], filename: str
) -> str:
    suffix = next((item for item in PYTHON_FIELDS if answer_id.endswith("-" + item)), None)
    if suffix is None:
        raise SolverError(f"{answer_id}: unrecognized Python answer field")
    if suffix == "role":
        return _role_and_attack(fields, filename)[0]
    if suffix == "attack":
        return _role_and_attack(fields, filename)[1]
    config_key = {
        "windows-chain": "windows_chain",
        "next-stage": "next_stage",
        "handoff-id": "handoff_id",
        "host-id": "host_id",
        "file-path": "file_path",
        "upload-url": "upload_url",
        "user-agent": "user_agent",
        "extension": "extension",
        "campaign": "campaign_id",
        "adapter": "adapter",
        "syntax": "syntax",
        "obfuscation": "obfuscation",
        "carrier": "carrier",
        "url": "url",
    }[suffix]
    value = fields.get(config_key, "")
    if not value:
        raise SolverError(f"{answer_id}: decoded Python configuration lacks {config_key}")
    return value


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    python_ids = {
        answer_id
        for answer_id in answer_ids
        if parse_answer_id(answer_id)[1].startswith("python-")
    }
    non_python_ids = [
        answer_id for answer_id in answer_ids if answer_id not in python_ids
    ]
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}

    if non_python_ids:
        shell_start = {
            **start,
            "answer_ids": non_python_ids,
            "questions": [questions[answer_id] for answer_id in non_python_ids],
        }
        shell_answers, shell_reasoning, shell_replay = shell_contrast.solve_detailed(
            shell_start, artifact_paths
        )
        if shell_replay != replay:
            raise SolverError("Shared shell solver returned an inconsistent replay state")
        answers.update(shell_answers)
        reasoning.update(shell_reasoning)

    all_members, members_by_artifact = collect_members(artifact_paths)
    python_members_by_artifact = [
        [
            (name, data)
            for name, data in members
            if pathlib.PurePosixPath(name).suffix.lower() == ".py"
        ]
        for members in members_by_artifact
    ]
    delivery_refs: dict[str, int | None] = {}
    for answer_id in python_ids:
        match = re.search(
            r"\bdelivery\s+(\d+)\b",
            artifact_hint(questions[answer_id]),
            re.IGNORECASE,
        )
        delivery_refs[answer_id] = max(0, int(match.group(1)) - 1) if match else None
    ordered_delivery_refs = sorted(
        {ref for ref in delivery_refs.values() if ref is not None}
    )
    if ordered_delivery_refs and len(ordered_delivery_refs) != len(artifact_paths):
        raise SolverError("Cannot map the assigned Python deliveries to their hints")

    cache: dict[str, tuple[dict[str, str], ast.AST]] = {}
    for answer_id in answer_ids:
        if answer_id not in python_ids:
            continue
        question = questions[answer_id]
        hint = artifact_hint(question).rsplit("->", 1)[-1].strip()
        python_members = all_members
        if len(artifact_paths) > 1:
            delivery_ref = delivery_refs[answer_id]
            if delivery_ref is None:
                raise SolverError(
                    f"{answer_id}: multiple artifact deliveries were assigned without "
                    "a delivery hint"
                )
            python_members = python_members_by_artifact[
                ordered_delivery_refs.index(delivery_ref)
            ]
        member_path, source_bytes = unique_by_hint(
            python_members, hint, description=f"Python carrier for {answer_id}"
        )
        if member_path not in cache:
            try:
                source = source_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise SolverError(f"{member_path}: recovered source is not UTF-8") from exc
            cache[member_path] = _decode_config(source, member_path)
        fields, _ = cache[member_path]
        value = _python_field_value(answer_id, fields, member_path)
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {member_path} using this question's member hint; parsed its AST "
            "and literal CODEC/material declarations, verified the decoder operators, "
            "recovered the configuration bytes without running the sample, and derived "
            "the requested field from its ordered steps or exact configuration value."
        )

    if set(answers) != set(answer_ids):
        raise SolverError("Python carrier analysis did not answer every returned field")
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically analyze Python carriers and bundled script specimens")


if __name__ == "__main__":
    main()
