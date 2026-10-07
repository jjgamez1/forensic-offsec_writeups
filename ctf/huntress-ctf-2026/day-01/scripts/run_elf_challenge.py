#!/usr/bin/env python3
"""Analyze assigned ELF artifact ZIPs and submit their answer fields."""

import argparse
import datetime
import io
import json
import pathlib
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile


PROXY = "http://10.0.0.219/huntress-ctf-proxy"
CHALLENGE_BASE = "binary-reverse-engineering-day-01-c-elf-orientation"
ELF_MAGIC = b"\x7fELF"
ZIP_MAGIC = b"PK"
ANSWER_FIELDS = {
    "elf_class",
    "endianness",
    "machine",
    "elf_type",
    "marker",
    "has_symtab",
    "exported_symbol",
    "recover_code",
    "entry_point",
}


def request(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {} if data is None else {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=12) as response:
        return response.read()


def game_master_start(challenge):
    return json.loads(request(PROXY, {"challenge": challenge}))


def game_master_prepare(challenge, timed):
    if timed:
        query = urllib.parse.urlencode({"op": "status", "challenge": challenge})
        try:
            status = json.loads(request(PROXY + "?" + query))
        except Exception:
            status = {}
        deadline = status.get("deadline")
        if deadline:
            try:
                expires = datetime.datetime.fromisoformat(
                    deadline.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                expires = 0
            if expires <= datetime.datetime.now(datetime.timezone.utc).timestamp():
                return json.loads(request(PROXY, {"op": "retry", "challenge": challenge}))
    return game_master_start(challenge)


def game_master_artifact(challenge, delivery=None):
    params = {"op": "artifact", "challenge": challenge}
    if delivery is not None:
        params["delivery"] = delivery
    query = urllib.parse.urlencode(params)
    return request(PROXY + "?" + query)


def collect_elfs(data, name, found):
    if data.startswith(ELF_MAGIC):
        found[name] = data
        return
    if not data.startswith(ZIP_MAGIC):
        return

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                collect_elfs(archive.read(item), f"{name}/{item.filename}", found)
    except zipfile.BadZipFile:
        return


def run_tool(*args):
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required ELF tool is unavailable: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() or exc.stdout.strip()
        raise RuntimeError(f"{' '.join(args)} failed: {details}") from exc
    return result.stdout


def labeled_value(text, label):
    match = re.search(rf"^\s*{re.escape(label)}:\s*(.*?)\s*$", text, re.MULTILINE)
    if not match:
        return "none"
    return match.group(1)


def analyze_elf(data, display_name):
    with tempfile.TemporaryDirectory(prefix="elf-aware-") as directory:
        path = pathlib.Path(directory) / pathlib.Path(display_name).name
        path.write_bytes(data)

        header = run_tool("readelf", "-h", "-W", str(path))
        sections = run_tool("readelf", "-S", "-W", str(path))
        symbols = run_tool("readelf", "-Ws", str(path))
        disassembly = run_tool("objdump", "-d", "-M", "intel", str(path))

        section_numbers = {}
        for line in sections.splitlines():
            match = re.match(r"^\s*\[\s*(\d+)\]\s+(\S+)", line)
            if match:
                section_numbers[match.group(2)] = match.group(1)

        marker_section = section_numbers.get(".huntress")
        marker_symbols = []
        if marker_section:
            for line in symbols.splitlines():
                match = re.match(
                    r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)",
                    line,
                )
                if match and match.group(1) == marker_section and match.group(2) != "UND":
                    marker_symbols.append(match.group(2))

        marker = "none"
        if ".huntress" in section_numbers:
            with tempfile.TemporaryDirectory(prefix="elf-section-") as directory:
                section_path = pathlib.Path(directory) / "huntress.bin"
                run_tool(
                    "objcopy",
                    "--dump-section",
                    f".huntress={section_path}",
                    str(path),
                )
                marker_bytes = section_path.read_bytes().split(b"\0", 1)[0]
                marker = marker_bytes.decode("utf-8", errors="replace") or "none"

        user_functions = []
        for line in symbols.splitlines():
            match = re.match(
                r"^\s*\d+:\s+\S+\s+(\d+)\s+FUNC\s+GLOBAL\s+DEFAULT\s+(\d+)\s+(\S+)",
                line,
            )
            if match and match.group(3) not in {"main", "_start"}:
                user_functions.append(match.group(3))
        designated_symbol = user_functions[0] if user_functions else "none"

        code_match = None
        if designated_symbol == "recover_code":
            body_match = re.search(
                rf"<{re.escape(designated_symbol)}>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
                disassembly,
                re.DOTALL,
            )
            body = body_match.group(1) if body_match else ""
            code_match = re.search(
                r"\bmov\s+e?ax,\s*0x([0-9a-fA-F]+)\b", body
            )
        recover_code = str(int(code_match.group(1), 16)) if code_match else "none"
        entry_point = labeled_value(header, "Entry point address")
        if entry_point != "none":
            entry_point = entry_point.lower()

        machine = labeled_value(header, "Machine")
        if "X86-64" in machine.upper():
            machine = "x86-64"

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

        answers = {
            "elf_class": labeled_value(header, "Class"),
            "endianness": endianness,
            "machine": machine,
            "elf_type": elf_type,
            "marker": marker,
            "has_symtab": "true" if ".symtab" in section_numbers else "false",
            "exported_symbol": designated_symbol,
            "recover_code": recover_code,
            "entry_point": entry_point,
        }
        return answers


def split_set_id(answer_id):
    nested = re.match(r"^(set\d+)\.(slot\d+)_(.+)$", answer_id)
    if nested:
        return f"{nested.group(1)}.{nested.group(2)}", nested.group(3)
    match = re.match(r"^(set\d+)\.(.+)$", answer_id)
    if not match:
        match = re.match(r"^(slot\d+)_(.+)$", answer_id)
    if match:
        return match.group(1), match.group(2)
    return None, answer_id


def assign_artifact_to_sets(start, found):
    questions = start.get("questions", [])
    set_artifacts = {}
    slot_sets = set()
    for question in questions:
        set_name, _ = split_set_id(question["id"])
        if set_name and set_name.startswith("slot"):
            slot_sets.add(set_name)
            continue
        if set_name and set_name not in set_artifacts:
            set_artifacts[set_name] = question.get("artifact", "").split(" -> ", 1)[0]

    by_set = {}
    if slot_sets:
        files = sorted(found.items(), key=lambda item: item[0])
        for set_name in sorted(slot_sets, key=lambda value: int(value[4:])):
            index = int(set_name[4:])
            explicit = [
                data
                for name, data in found.items()
                if re.search(rf"(?:^|/)slot-{index}\.elf$", name)
            ]
            if len(explicit) == 1:
                by_set[set_name] = explicit[0]
                continue
            if index >= len(files):
                raise RuntimeError(f"No ELF artifact found for {set_name}")
            by_set[set_name] = files[index][1]
        return by_set
    if not set_artifacts:
        if len(found) != 1:
            raise RuntimeError(f"Expected one ELF for this mode; found {len(found)}")
        by_set[None] = next(iter(found.values()))
        return by_set

    for set_name, artifact_name in set_artifacts.items():
        artifact_basename = pathlib.PurePosixPath(artifact_name).name
        delivery_match = re.search(r"\bdelivery\s+(\d+)\b", artifact_name, re.I)
        slot_match = re.match(r"^set\d+\.slot(\d+)$", set_name)
        matches = [
            data
            for name, data in found.items()
            if name == artifact_name
            or name.startswith(artifact_name + "/")
            or f"/{artifact_basename}/" in f"/{name}/"
            or (
                delivery_match
                and name.startswith(f"delivery-{delivery_match.group(1)}/")
            )
            and (
                not slot_match
                or re.search(rf"(?:^|/)m?-?slot-{slot_match.group(1)}\.elf$", name)
            )
        ]
        if not matches and len(set_artifacts) == 1 and len(found) == 1:
            matches = list(found.values())
        if len(matches) != 1:
            raise RuntimeError(
                f"Could not map {set_name} ({artifact_name}) to exactly one ELF; "
                f"found {len(matches)}"
            )
        by_set[set_name] = matches[0]
    return by_set


def build_answers(start, by_set):
    analyzed = {key: analyze_elf(value, str(key)) for key, value in by_set.items()}
    answers = {}
    for answer_id in start["answer_ids"]:
        set_name, field = split_set_id(answer_id)
        if field not in ANSWER_FIELDS:
            raise RuntimeError(f"Unexpected answer field from Game Master: {answer_id}")
        if set_name not in analyzed:
            raise RuntimeError(f"No assigned ELF was analyzed for {answer_id}")
        answers[answer_id] = analyzed[set_name][field]
    return analyzed, answers


def main():
    parser = argparse.ArgumentParser(
        description="Start an ELF challenge, analyze its assigned ELF bytes, and submit answers."
    )
    parser.add_argument(
        "--mode",
        choices=("single_solve", "time_trial", "mastery"),
        default="single_solve",
    )
    args = parser.parse_args()

    challenge = CHALLENGE_BASE
    if args.mode != "single_solve":
        challenge += "/" + args.mode

    started = game_master_prepare(challenge, args.mode != "single_solve")
    found = {}
    if args.mode == "mastery":
        delivery_map = {}
        for question in started.get("questions", []):
            set_name, _ = split_set_id(question["id"])
            match = re.search(r"\bdelivery\s+(\d+)\b", question.get("artifact", ""), re.I)
            if set_name and match:
                delivery = int(match.group(1))
                base_set = re.match(r"^(set\d+)", set_name)
                delivery_map[base_set.group(1) if base_set else set_name] = delivery
        for delivery in sorted(set(delivery_map.values())):
            collect_elfs(
                game_master_artifact(challenge, delivery=delivery - 1),
                f"delivery-{delivery}",
                found,
            )
    else:
        collect_elfs(game_master_artifact(challenge), "artifact", found)
    if not found:
        raise RuntimeError("The assigned artifact ZIP contained no ELF executable")

    by_set = assign_artifact_to_sets(started, found)
    analyzed, answers = build_answers(started, by_set)
    if args.mode == "single_solve":
        result = json.loads(request(PROXY, {"challenge": challenge, "answers": answers}))
        submissions = [{"answer_count": len(answers), "result": result.get("result")}]
    else:
        result = {}
        submissions = []
        grouped = {}
        for answer_id, answer in answers.items():
            set_name, _ = split_set_id(answer_id)
            grouped.setdefault(set_name or "single", {})[answer_id] = answer
        for group_name, group_answers in grouped.items():
            result = json.loads(
                request(
                    PROXY,
                    {"challenge": challenge, "answers": group_answers},
                )
            )
            submissions.append(
                {
                    "group": group_name,
                    "answer_count": len(group_answers),
                    "result": result.get("result"),
                    "remaining": result.get("remaining"),
                }
            )
            if result.get("result") == "CORRECT":
                break
    print(
        json.dumps(
            {
                "attempt_id": started.get("attempt_id"),
                "deadline": started.get("deadline"),
                "analyzed": analyzed,
                "answers_submitted": answers,
                "field_submissions": submissions,
                "result": result.get("result"),
                "flag": result.get("flag"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
