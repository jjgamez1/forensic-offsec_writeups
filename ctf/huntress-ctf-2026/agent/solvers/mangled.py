#!/usr/bin/env python3
"""Statically inspect the assigned C and C++ ELF evidence set."""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import re
import struct
import subprocess
import tempfile
import zipfile
import zlib
from typing import Any

from agent.answer_ids import parse_answer_id
from agent.solvers.common import (
    SolverError,
    artifact_hint,
    answer_ids_and_replay,
    elf_machine_name,
    hinted_member,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)


ELF_MAGIC = b"\x7fELF"
ZIP_PASSWORD = b"infected"


def run_static_tool(*args: str) -> str:
    import subprocess

    try:
        result = subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=8
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SolverError(f"Required static tool is unavailable: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise SolverError(f"{args[0]} could not inspect assigned bytes: {detail}") from exc
    return result.stdout


def _members(data: bytes, label: str, depth: int = 0) -> list[tuple[str, bytes]]:
    if depth > 8:
        raise SolverError("Nested ZIP depth exceeds the inspection limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            encrypted = any(info.flag_bits & 1 for info in infos)
    except zipfile.BadZipFile:
        return [(label, data)]

    if encrypted:
        try:
            import pyzipper

            with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
                archive.pwd = ZIP_PASSWORD
                children = [
                    (f"{label}/{info.filename}", archive.read(info))
                    for info in archive.infolist()
                    if not info.is_dir()
                ]
        except ImportError as exc:
            raise SolverError(
                "AES ZIP reading requires pyzipper in the configured Python environment"
            ) from exc
        except (RuntimeError, ValueError, OSError, zipfile.BadZipFile) as exc:
            raise SolverError(f"Could not read assigned AES ZIP {label}") from exc
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            children = [
                (f"{label}/{info.filename}", archive.read(info))
                for info in archive.infolist()
                if not info.is_dir()
            ]

    result: list[tuple[str, bytes]] = []
    for child_label, child_data in children:
        result.extend(_members(child_data, child_label, depth + 1))
    return result


def assigned_members(paths: list[pathlib.Path]) -> tuple[
    list[tuple[str, bytes]], list[list[tuple[str, bytes]]]
]:
    all_members = []
    by_artifact = []
    for path, data in load_artifacts(paths):
        found = _members(data, path.name)
        by_artifact.append(found)
        all_members.extend(found)
    return all_members, by_artifact


def _section_bytes(data: bytes, display_name: str, section: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="ctf-mangled-static-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(display_name).name
        path.write_bytes(data)
        sections = run_static_tool("readelf", "-SW", str(path))
        section_line = None
        for line in sections.splitlines():
            columns = line.split()
            if len(columns) >= 7 and columns[1] == section:
                section_line = columns
                break
        if section_line is None:
            raise SolverError(f"{display_name}: ELF section {section} is absent")
        offset = int(section_line[4], 16)
        size = int(section_line[5], 16)
    result = data[offset : offset + size]
    if len(result) != size:
        raise SolverError(f"{display_name}: ELF section {section} is truncated")
    return result


def _read_symbol_names(data: bytes, display_name: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="ctf-mangled-static-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(display_name).name
        path.write_bytes(data)
        output = run_static_tool("readelf", "-Ws", str(path))
    names = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].rstrip(":").isdigit():
            name = fields[-1]
            if name not in {"", "UND"} and not name.startswith("_GLOBAL_"):
                names.append(name)
    return list(dict.fromkeys(names))


def analyze_c(data: bytes, label: str) -> dict[str, str]:
    if not data.startswith(ELF_MAGIC):
        raise SolverError(f"{label}: C specimen is not an ELF file")
    with tempfile.TemporaryDirectory(prefix="ctf-mangled-c-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(label).name
        path.write_bytes(data)
        header = run_static_tool("readelf", "-h", "-W", str(path))
        sections = run_static_tool("readelf", "-SW", str(path))
        disassembly = run_static_tool("objdump", "-d", "-M", "intel", str(path))

    machine_match = re.search(r"^\s*Machine:\s*(.*?)\s*$", header, re.MULTILINE)
    if not machine_match:
        raise SolverError(f"{label}: ELF machine field was not present")
    machine = elf_machine_name(machine_match.group(1))
    marker = _section_bytes(data, label, ".huntress").split(b"\0", 1)[0]
    try:
        marker_text = marker.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SolverError(f"{label}: marker section is not UTF-8") from exc

    recover_match = re.search(
        r"<recover_code>:\s*\n(.*?)(?=\n[0-9a-fA-F]+ <|\Z)",
        disassembly,
        re.DOTALL,
    )
    immediate = (
        re.search(r"\bmov\s+(?:e?ax),\s*0x([0-9a-fA-F]+)\b", recover_match.group(1))
        if recover_match
        else None
    )
    if not immediate:
        raise SolverError(f"{label}: recover_code immediate was not statically identified")
    has_symtab = bool(
        re.search(r"^\s*\[\s*\d+\]\s+\.symtab\b", sections, re.MULTILINE)
    )
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "marker": marker_text or "none",
        "has_symtab": "true" if has_symtab else "false",
        "recover_code": str(int(immediate.group(1), 16)),
        "machine": machine,
    }


def analyze_cpp(data: bytes, label: str) -> dict[str, str]:
    if not data.startswith(ELF_MAGIC):
        return {}
    section = _section_bytes(data, label, ".hcfg")
    if len(section) < 12 or section[:4] != b"HCFG" or section[4] != 1:
        raise SolverError(f"{label}: unsupported HCFG header")
    xor_key = section[5]
    declared_length = struct.unpack_from("<H", section, 6)[0]
    encoded_config = section[12 : 12 + declared_length]
    if len(encoded_config) != declared_length:
        raise SolverError(f"{label}: HCFG payload length does not match its header")
    config_bytes = bytes(value ^ xor_key for value in encoded_config)
    try:
        config = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError(f"{label}: decoded HCFG payload is not UTF-8 JSON") from exc
    if not isinstance(config, dict):
        raise SolverError(f"{label}: decoded HCFG payload is not an object")

    symbols = _read_symbol_names(data, label)
    vtable_candidates = [
        symbol
        for symbol in symbols
        if symbol.startswith("_ZTV") and "__cxxabiv" not in symbol
    ]
    typeinfo_candidates = [
        symbol
        for symbol in symbols
        if symbol.startswith("_ZTI") and "__cxxabiv" not in symbol
    ]
    score_candidates = [
        symbol for symbol in symbols if symbol.startswith("_Z") and "score" in symbol
    ]
    if len(vtable_candidates) > 1 or len(score_candidates) > 1:
        raise SolverError(f"{label}: C++ metadata has ambiguous vtable or score symbols")
    if score_candidates:
        demangled = run_static_tool("c++filt", score_candidates[0]).strip()
        if "score(" not in demangled:
            raise SolverError(f"{label}: score symbol did not demangle as a method")
    else:
        raise SolverError(f"{label}: mangled score symbol was not present")
    fields = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": "ELF",
        "xor_key": f"0x{xor_key:02x}",
        "config_crc32": f"0x{zlib.crc32(config_bytes) & 0xffffffff:08x}",
        "campaign": str(config.get("campaign", "")),
        "domain": str(config.get("domain", "")),
        "url": str(config.get("url", "")),
        "mutex": str(config.get("mutex", "")),
        "has_vtable": "true" if vtable_candidates else "false",
        "has_typeinfo": "true" if typeinfo_candidates else "false",
        "mangled_score_symbol": score_candidates[0],
        "vtable_symbol": vtable_candidates[0] if vtable_candidates else "none",
    }
    if any(not value for key, value in fields.items() if key not in {"vtable_symbol"}):
        raise SolverError(f"{label}: decoded C++ evidence is missing a requested field")
    return fields


def _objdump_supports_pe() -> bool:
    try:
        result = subprocess.run(
            ("objdump", "-i"),
            check=True,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False
    return bool(re.search(r"(?m)^\s*pei?-(?:i386|x86-64)\b", result.stdout))


def analyze_pe(data: bytes, label: str) -> dict[str, Any]:
    if not data.startswith(b"MZ"):
        raise SolverError(f"{label}: PE specimen does not start with MZ magic bytes")
    if not _objdump_supports_pe():
        raise SolverError(
            f"{label}: installed objdump does not advertise the PE formats needed for static import inspection"
        )
    with tempfile.TemporaryDirectory(prefix="ctf-mangled-pe-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(label).name
        path.write_bytes(data)
        output = run_static_tool("objdump", "-p", str(path))
        section_path = pathlib.Path(directory) / "hcfg.bin"
        run_static_tool(
            "objcopy",
            "--dump-section",
            f".hcfg={section_path}",
            str(path),
        )
        try:
            section = section_path.read_bytes()
        except OSError as exc:
            raise SolverError(f"{label}: objcopy did not produce the .hcfg section") from exc
        symbol_output = run_static_tool("objdump", "-t", str(path))
    if not re.search(r"(?m)^.*:\s+file format pe(?:i)?-", output):
        raise SolverError(f"{label}: objdump did not identify the MZ file as PE")

    imports: list[tuple[str, list[str]]] = []
    current_dll: str | None = None
    in_import_table = False
    for line in output.splitlines():
        if re.search(r"\bThe Import Tables\b", line):
            in_import_table = True
            current_dll = None
            continue
        if in_import_table and re.match(r"\s*The .+ Tables\b", line):
            in_import_table = False
            current_dll = None
        if not in_import_table:
            continue
        dll_match = re.match(r"\s*DLL Name:\s*(\S.*?)\s*$", line)
        if dll_match:
            current_dll = dll_match.group(1)
            imports.append((current_dll, []))
            continue
        if current_dll is None:
            continue
        symbol_match = re.match(
            r"\s*[0-9a-fA-F]+\s+\d+\s+([A-Za-z_?$@.][^\s]*)\s*$",
            line,
        )
        if symbol_match:
            imports[-1][1].append(symbol_match.group(1))
        elif re.match(r"\s*[0-9a-fA-F]+\s+\[\s*\d+\]\s*$", line):
            raise SolverError(
                f"{label}: objdump reports ordinal-only imports that cannot be returned as literal names"
            )
    if not imports:
        if re.search(r"(?m)^\s*The Import Tables", output):
            imports = []
        else:
            raise SolverError(f"{label}: objdump output has no recognizable import table")
    if len(section) < 12 or section[:4] != b"HCFG" or section[4] != 1:
        raise SolverError(f"{label}: PE .hcfg section has an unsupported header")
    xor_key = section[5]
    declared_length = struct.unpack_from("<H", section, 6)[0]
    encoded_config = section[12 : 12 + declared_length]
    if len(encoded_config) != declared_length:
        raise SolverError(f"{label}: PE .hcfg payload length does not match its header")
    config_bytes = bytes(value ^ xor_key for value in encoded_config)
    try:
        config = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolverError(f"{label}: decoded PE HCFG payload is not UTF-8 JSON") from exc
    if not isinstance(config, dict):
        raise SolverError(f"{label}: decoded PE HCFG payload is not a JSON object")

    symbols = []
    for line in symbol_output.splitlines():
        for token in line.split():
            if token.startswith(("_ZTV", "_ZTI", "_ZN")):
                symbols.append(token)
    symbols = list(dict.fromkeys(symbols))
    vtables = [
        symbol
        for symbol in symbols
        if symbol.startswith("_ZTV")
        and "__cxxabiv" not in symbol
        and not symbol.startswith("_ZTVSt")
    ]
    typeinfos = [
        symbol
        for symbol in symbols
        if symbol.startswith("_ZTI")
        and "__cxxabiv" not in symbol
        and not symbol.startswith("_ZTISt")
    ]
    scores = [symbol for symbol in symbols if symbol.startswith("_Z") and "score" in symbol]
    if len(vtables) > 1 or len(scores) != 1:
        raise SolverError(f"{label}: PE C++ metadata has ambiguous or missing symbols")
    demangled = run_static_tool("c++filt", scores[0]).strip()
    if "score(" not in demangled:
        raise SolverError(f"{label}: PE score symbol did not demangle as a method")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": "PE",
        "imports": imports,
        "xor_key": f"0x{xor_key:02x}",
        "config_crc32": f"0x{zlib.crc32(config_bytes) & 0xffffffff:08x}",
        "campaign": str(config.get("campaign", "")),
        "domain": str(config.get("domain", "")),
        "url": str(config.get("url", "")),
        "mutex": str(config.get("mutex", "")),
        "has_vtable": "true" if vtables else "false",
        "has_typeinfo": "true" if typeinfos else "false",
        "mangled_score_symbol": scores[0],
        "vtable_symbol": vtables[0] if vtables else "none",
    }


def answer_pe_import(
    answer_id: str, question: dict[str, Any], pe_fields: dict[str, Any]
) -> str:
    question_text = str(question.get("question", "")).casefold()
    syntax = str(question.get("answer_format", {}).get("syntax", "")).casefold()
    dlls = [dll for dll, _ in pe_fields["imports"]]
    symbols = [symbol for _, names in pe_fields["imports"] for symbol in names]
    asks_dlls = any(token in question_text for token in ("dll", "library", "module"))
    asks_symbols = any(token in question_text for token in ("function", "symbol", "api"))
    plural = bool(
        re.search(
            r"\b(imports|dlls|libraries|modules|functions|symbols|apis|all|list)\b",
            question_text,
        )
        or "comma-separated" in syntax
        or "comma separated" in syntax
        or "json array" in syntax
        or "json list" in syntax
    )
    if asks_dlls and not asks_symbols:
        values = list(dict.fromkeys(dlls))
        subject = "DLL names"
    elif asks_symbols and not asks_dlls:
        named_dlls_in_question = [
            dll
            for dll in dlls
            if dll.casefold() in question_text
        ]
        if len(named_dlls_in_question) > 1:
            raise SolverError(
                f"{answer_id}: question names multiple DLLs without a clear symbol grouping"
            )
        symbol_groups = [
            names
            for dll, names in pe_fields["imports"]
            if not named_dlls_in_question
            or dll.casefold() == named_dlls_in_question[0].casefold()
        ]
        values = list(dict.fromkeys(symbol for names in symbol_groups for symbol in names))
        subject = "imported symbol names"
    elif asks_dlls and asks_symbols and (
        "dll!symbol" in syntax or "dll!function" in syntax
    ):
        values = list(
            dict.fromkeys(
                f"{dll}!{symbol}"
                for dll, names in pe_fields["imports"]
                for symbol in names
            )
        )
        subject = "DLL!symbol pairs"
    else:
        raise SolverError(
            f"{answer_id}: the returned question and format do not identify an unambiguous literal PE import representation"
        )
    if not values:
        raise SolverError(f"{answer_id}: the assigned PE has no named {subject}")
    if not plural:
        if len(values) != 1:
            raise SolverError(
                f"{answer_id}: the question asks for one {subject}, but the PE contains {len(values)}"
            )
        return values[0]
    if "comma-separated" in syntax or "comma separated" in syntax:
        return ", ".join(values)
    if "json array" in syntax or "json list" in syntax:
        return json.dumps(values, ensure_ascii=False)
    raise SolverError(
        f"{answer_id}: multiple {subject} are present but the answer format specifies no supported list encoding"
    )


def specimen_type(data: bytes, label: str) -> str:
    if data.startswith(b"MZ"):
        return "cpp"
    if not data.startswith(ELF_MAGIC):
        return "other"
    try:
        _section_bytes(data, label, ".hcfg")
        return "cpp"
    except SolverError:
        try:
            _section_bytes(data, label, ".huntress")
            return "c"
        except SolverError:
            return "other"


def field_name(answer_id: str) -> str:
    _, field = parse_answer_id(answer_id)
    return field


def choose_specimen(
    answer_id: str,
    question: dict[str, Any],
    candidates: list[tuple[str, bytes]],
) -> tuple[str, bytes]:
    hint = hinted_member(question)
    if hint:
        return unique_by_hint(candidates, hint, description=f"evidence for {answer_id}")

    requested_field = field_name(answer_id)
    expected_type = "c" if requested_field.startswith("c_") else "cpp"
    typed = [
        (path, data)
        for path, data in candidates
        if specimen_type(data, path) == expected_type
    ]
    if len(typed) != 1:
        raise SolverError(
            f"{answer_id}: expected one {expected_type.upper()} specimen in the hinted delivery, found {len(typed)}"
        )
    return typed[0]


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    members, members_by_artifact = assigned_members(artifact_paths)

    delivery_refs = {}
    for answer_id in answer_ids:
        match = re.search(
            r"\bdelivery\s+(\d+)\b",
            artifact_hint(questions[answer_id]),
            re.IGNORECASE,
        )
        delivery_refs[answer_id] = max(0, int(match.group(1)) - 1) if match else None
    c_cache: dict[str, dict[str, str]] = {}
    cpp_cache: dict[str, dict[str, Any]] = {}
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id in answer_ids:
        question = questions[answer_id]
        delivery_ref = delivery_refs[answer_id]
        scoped = members
        if delivery_ref is not None:
            if delivery_ref >= len(members_by_artifact):
                raise SolverError(
                    f"{answer_id}: delivery {delivery_ref + 1} was not downloaded"
                )
            scoped = members_by_artifact[delivery_ref]
        label, data = choose_specimen(answer_id, question, scoped)
        kind = "c" if field_name(answer_id).startswith("c_") else "cpp"
        if kind == "c":
            if label not in c_cache:
                c_cache[label] = analyze_c(data, label)
            cache = c_cache[label]
            mapping = {
                "c_sha256": "sha256",
                "c_marker": "marker",
                "c_has_symtab": "has_symtab",
                "c_recover_code": "recover_code",
                "c_machine": "machine",
            }
        else:
            if label not in cpp_cache:
                cpp_cache[label] = (
                    analyze_pe(data, label)
                    if data.startswith(b"MZ")
                    else analyze_cpp(data, label)
                )
            cache = cpp_cache[label]
            mapping = {
                "cpp_sha256": "sha256",
                "cpp_format": "format",
                "cpp_xor_key": "xor_key",
                "cpp_config_crc32": "config_crc32",
                "campaign": "campaign",
                "domain": "domain",
                "url": "url",
                "mutex": "mutex",
                "has_cpp_vtable": "has_vtable",
                "has_cpp_typeinfo": "has_typeinfo",
                "mangled_score_symbol": "mangled_score_symbol",
                "vtable_symbol": "vtable_symbol",
            }
            if data.startswith(b"MZ") and (
                "import" in field_name(answer_id).casefold()
                or "import" in str(question.get("question", "")).casefold()
            ):
                value = answer_pe_import(answer_id, question, cache)
                validate_answer_format(answer_id, value, question)
                answers[answer_id] = value
                reasoning[answer_id] = (
                    f"Selected {label} from this question's assigned delivery, verified its "
                    "MZ magic, and read its PE import table using objdump -p without executing it."
                )
                continue
        source_field = mapping.get(field_name(answer_id))
        if source_field is None or source_field not in cache:
            raise SolverError(f"{answer_id}: no static evidence mapping is registered")
        value = cache[source_field]
        validate_answer_format(answer_id, value, question)
        answers[answer_id] = value
        reasoning[answer_id] = (
            f"Selected {label} from this question's assigned delivery and inspected its "
            "header/sections/symbols statically; literal symbol and configuration strings "
            "were preserved, and no binary was executed."
        )
    return answers, reasoning, replay


def solve(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> dict[str, str]:
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Statically analyze assigned C and C++ ELF evidence")


if __name__ == "__main__":
    main()
