#!/usr/bin/env python3
"""Statically inspect assigned ELF binaries and map findings to returned questions."""

from __future__ import annotations

import io
import pathlib
import re
import subprocess
import tempfile
import zipfile
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    elf_machine_name,
    hinted_member,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


ELF_MAGIC = b"\x7fELF"


def run_tool(*args: str) -> str:
    try:
        result = subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=8
        )
    except FileNotFoundError as exc:
        raise SolverError(f"Required static ELF tool is unavailable: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SolverError(f"Static ELF tool timed out: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise SolverError(f"{args[0]} could not inspect the assigned ELF: {detail}") from exc
    return result.stdout


def collect_elfs(
    path: pathlib.Path, data: bytes
) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = []

    def visit(label: str, current: bytes, depth: int = 0) -> None:
        if depth > 8:
            raise SolverError("Nested ZIP depth exceeds the safe inspection limit")
        if current.startswith(ELF_MAGIC):
            found.append((label, current))
            return
        if not current.startswith(b"PK\x03\x04"):
            return
        try:
            with zipfile.ZipFile(io.BytesIO(current)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if info.flag_bits & 1:
                        raise SolverError(
                            f"Encrypted ZIP member {info.filename!r} cannot be inspected"
                        )
                    visit(f"{label}/{info.filename}", archive.read(info), depth + 1)
        except zipfile.BadZipFile as exc:
            raise SolverError(f"Could not parse ZIP bytes in {label}") from exc

    visit(path.name, data)
    return found


def labeled_value(text: str, label: str) -> str:
    match = re.search(
        rf"^\s*{re.escape(label)}:\s*(.*?)\s*$", text, re.MULTILINE
    )
    return match.group(1) if match else "none"


def field_is_optional(question: dict[str, Any]) -> bool:
    answer_format = question.get("answer_format", {})
    syntax = str(answer_format.get("syntax", "")).lower()
    accepted = answer_format.get("accepted_values", [])
    return "literal none" in syntax or (
        isinstance(accepted, list) and "none" in accepted
    )


def question_function_name(questions: list[dict[str, Any]]) -> str | None:
    for question in questions:
        text = str(question.get("question", ""))
        match = re.search(r"\breturned by\s+([A-Za-z_][A-Za-z0-9_]*)", text)
        if match:
            return match.group(1)
    return None


def requested_section(
    questions: list[dict[str, Any]], pattern: str, description: str
) -> str:
    for question in questions:
        text = str(question.get("question", ""))
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    raise SolverError(f"Returned questions do not identify the requested {description}")


def analyze_elf(
    data: bytes, display_name: str, questions: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, str]]:
    marker_section_name = requested_section(
        questions,
        r"custom\s+([.A-Za-z0-9_]+)\s+section",
        "marker section name",
    )
    symtab_section_name = requested_section(
        questions,
        r"retain\s+(?:a|an)\s+([.A-Za-z0-9_]+)\s+section",
        "symbol-table section name",
    )
    with tempfile.TemporaryDirectory(prefix="ctf-elf-static-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(display_name).name
        path.write_bytes(data)
        header = run_tool("readelf", "-h", "-W", str(path))
        sections_text = run_tool("readelf", "-S", "-W", str(path))
        symbols_text = run_tool("readelf", "-Ws", str(path))
        disassembly = run_tool("objdump", "-d", "-M", "intel", str(path))

        sections: dict[str, str] = {}
        for line in sections_text.splitlines():
            match = re.match(r"^\s*\[\s*(\d+)\]\s+(\S+)", line)
            if match:
                sections[match.group(2)] = match.group(1)

        marker = "none"
        if marker_section_name in sections:
            marker_path = pathlib.Path(directory) / "marker.bin"
            run_tool(
                "objcopy",
                "--dump-section",
                f"{marker_section_name}={marker_path}",
                str(path),
            )
            try:
                marker = marker_path.read_bytes().split(b"\0", 1)[0].decode(
                    "utf-8", errors="strict"
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise SolverError("The custom marker section is not readable UTF-8") from exc
            marker = marker or "none"

        user_functions: list[str] = []
        for line in symbols_text.splitlines():
            match = re.match(
                r"^\s*\d+:\s+\S+\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+(\S+)\s+(\S+)",
                line,
            )
            if (
                match
                and match.group(1) != "UND"
                and match.group(2) not in {"main", "_start"}
            ):
                user_functions.append(match.group(2))
        user_functions = list(dict.fromkeys(user_functions))

        requested_function = question_function_name(questions)
        if requested_function in user_functions:
            designated_symbol = requested_function
        elif len(user_functions) == 1:
            designated_symbol = user_functions[0]
        elif not user_functions:
            designated_symbol = "none"
        else:
            raise SolverError(
                "Several candidate global functions exist and the returned questions "
                "do not identify which one is designated"
            )

        recover_code = "none"
        if requested_function and requested_function in user_functions:
            body_match = re.search(
                rf"<{re.escape(requested_function)}>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
                disassembly,
                re.DOTALL,
            )
            body = body_match.group(1) if body_match else ""
            immediate = re.search(
                r"\bmov\s+(?:e?ax),\s*0x([0-9a-fA-F]+)\b", body
            )
            if immediate:
                recover_code = str(int(immediate.group(1), 16))

        elf_type = labeled_value(header, "Type")
        type_match = re.match(r"([A-Z_]+)", elf_type)
        if type_match:
            elf_type = "ET_" + type_match.group(1)
        data_description = labeled_value(header, "Data").lower()
        if "little endian" in data_description:
            endianness = "little"
        elif "big endian" in data_description:
            endianness = "big"
        else:
            endianness = data_description
        machine = elf_machine_name(labeled_value(header, "Machine"))
        entry_point = labeled_value(header, "Entry point address").lower()
        if entry_point == "none":
            entry_point = "none"

        fields = {
            "elf_class": labeled_value(header, "Class"),
            "endianness": endianness,
            "machine": machine,
            "elf_type": elf_type,
            "marker": marker,
            "has_symtab": (
                "true" if symtab_section_name in sections else "false"
            ),
            "exported_symbol": designated_symbol,
            "recover_code": recover_code,
            "entry_point": entry_point,
        }
        evidence = {
            "elf_class": "ELF header Class field",
            "endianness": "ELF header Data field",
            "machine": "ELF header Machine field",
            "elf_type": "ELF header Type field",
            "marker": f"custom {marker_section_name} section bytes",
            "has_symtab": f"section table presence of {symtab_section_name}",
            "exported_symbol": "defined global function symbols, excluding entry functions",
            "recover_code": (
                f"static disassembly of {requested_function}"
                if requested_function
                else "no function name was requested by the returned questions"
            ),
            "entry_point": "ELF header Entry point address field",
        }
        return fields, evidence


def scope_and_field(identifier: str) -> tuple[str | None, str]:
    return parse_answer_id(identifier)


def choose_elf(
    scope: str | None,
    group_questions: list[dict[str, Any]],
    candidates: list[tuple[str, bytes]],
) -> tuple[str, bytes]:
    if len(candidates) == 1:
        return candidates[0]

    for question in group_questions:
        hint = artifact_hint(question).replace("\\", "/")
        member = hinted_member(question)
        if member:
            try:
                return unique_by_hint(candidates, member, description="ELF member")
            except SolverError:
                pass

        delivery = re.search(r"\bdelivery\s+(\d+)\b", hint, re.IGNORECASE)
        slot = re.search(r"\bslot[-\s]?(\d+)\b", hint, re.IGNORECASE)
        if not slot and scope:
            slot = re.search(r"\bslot(\d+)\b", scope, re.IGNORECASE)
        filtered = candidates
        if delivery:
            delivery_name = f"delivery-{int(delivery.group(1))}"
            filtered = [item for item in filtered if delivery_name in item[0]]
        if slot:
            slot_num = int(slot.group(1))
            slot_pattern = re.compile(
                rf"(?:^|[/_-])(?:m-?)?slot[-_]?{slot_num}(?:\.|[/_-]|$)",
                re.IGNORECASE,
            )
            filtered = [item for item in filtered if slot_pattern.search(item[0])]
        if len(filtered) == 1:
            return filtered[0]

    raise SolverError(
        f"Could not map {scope or 'unscoped questions'} to one of "
        f"{len(candidates)} assigned ELF files using returned artifact references"
    )


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    loaded = load_artifacts(artifact_paths)
    candidates = [
        elf
        for path, data in loaded
        for elf in collect_elfs(path, data)
    ]
    if not candidates:
        raise SolverError("No ELF magic bytes were found in the assigned artifacts")

    grouped: dict[str | None, list[tuple[str, dict[str, Any]]]] = {}
    for answer_id, question in questions.items():
        scope, _ = scope_and_field(answer_id)
        grouped.setdefault(scope, []).append((answer_id, question))

    analyzed: dict[
        str | None, tuple[str, dict[str, str], dict[str, str]]
    ] = {}
    for scope, entries in grouped.items():
        group_questions = [question for _, question in entries]
        elf_name, elf_bytes = choose_elf(scope, group_questions, candidates)
        fields, evidence = analyze_elf(elf_bytes, elf_name, group_questions)
        analyzed[scope] = (elf_name, fields, evidence)

    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id, question in questions.items():
        scope, field = scope_and_field(answer_id)
        elf_name, fields, evidence = analyzed[scope]
        if field not in fields:
            prompt = str(question.get("question", "")).lower()
            aliases = {
                "architecture": "machine",
                "byte_order": "endianness",
                "object_type": "elf_type",
                "symbol": "exported_symbol",
                "entry": "entry_point",
            }
            field = aliases.get(field, field)
            if field not in fields:
                raise SolverError(f"Cannot determine ELF field for {answer_id!r}")
        value = fields[field]
        if value == "none" and not field_is_optional(question):
            raise SolverError(
                f"{answer_id}: requested ELF field is absent and the answer format "
                "does not allow none"
            )
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Read {evidence[field]} from the ELF at {elf_name!r}; "
            f"identified by its ELF magic bytes."
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    """Return answers keyed by the exact IDs in this start response."""
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically inspect assigned ELF artifacts")


if __name__ == "__main__":
    main()
