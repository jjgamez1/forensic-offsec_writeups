#!/usr/bin/env python3
"""Run registered Huntress CTF solvers against the current player's assignments."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import zipfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "agent"
sys.path.insert(0, str(ROOT))

from agent.answer_ids import parse_answer_id  # noqa: E402
from agent.gm_client import GMClient, delivery_indexes  # noqa: E402
from agent.runtime import (  # noqa: E402
    RuntimeEnvironmentError,
    configured_python,
    dependency_preflight,
    format_preflight_errors,
    reexec_in_configured_environment,
)
from agent.solvers.common import (  # noqa: E402
    SolverError,
    questions_by_id,
    validate_answer_format,
)


REGISTRY_PATH = AGENT_DIR / "registry.json"
RUNS_DIR = AGENT_DIR / "runs"
ARTIFACTS_DIR = AGENT_DIR / "artifacts"
NOTES_DIR = AGENT_DIR / "notes"
STATE_PATH = AGENT_DIR / "state" / "submissions.json"
TIMED_MODES = ("time_trial", "mastery")
MODE_ORDER = ("single_solve", "time_trial", "mastery")
MODE_SUFFIXES = ("/time_trial", "/mastery")
PRIVATE_VALUES: set[str] = set()


class AgentError(RuntimeError):
    """A safe, actionable error that should stop this challenge run."""


class DependencyRequired(AgentError):
    """A solver dependency is missing; dependency installation requires approval."""


class SubmissionUncertain(AgentError):
    """A submission may have reached the service; never retry it blindly."""


class SubmissionPolicyError(AgentError):
    """A resubmission needs a diagnosis and a changed solver or answer set."""


class SubmissionLimitReached(AgentError):
    """The submission cap for this challenge mode has been reached."""


def register_private_value(value: str) -> None:
    if len(value) >= 8:
        PRIVATE_VALUES.add(value)


def safe_public_text(value: str) -> str:
    for private_value in PRIVATE_VALUES:
        value = value.replace(private_value, "[private value withheld]")
    return value


def safe_public_data(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if str(key).casefold() in {"flag", "flags", "target_flag"}:
                result[key] = "[private value withheld]"
            else:
                result[key] = safe_public_data(item)
        return result
    if isinstance(value, list):
        return [safe_public_data(item) for item in value]
    if isinstance(value, str):
        return safe_public_text(value)
    return value


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json(path: pathlib.Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(mode=0o700 if private else 0o755, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if not private:
        value = safe_public_data(value)
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if private:
        os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def read_state() -> dict[str, Any]:
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"submissions": {}, "handed_back": []}
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError(f"Could not read state file {STATE_PATH}") from exc
    if not isinstance(state, dict):
        raise AgentError("Submission state must be a JSON object")
    state.setdefault("submissions", {})
    state.setdefault("handed_back", [])
    return state


def log_event(log_path: pathlib.Path, event: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = safe_public_data(
        {"time": dt.datetime.now(dt.timezone.utc).isoformat(), **event}
    )
    with log_path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def answer_fingerprint(answers: dict[str, str]) -> str:
    serialized = json.dumps(answers, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def file_fingerprint(path: pathlib.Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise AgentError(f"Cannot read solver source {path}") from exc


def safe_component(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return result or "unknown"


def mode_id(base_id: str, mode: str) -> str:
    if mode == "single_solve":
        return base_id
    return f"{base_id}/{mode}"


def base_challenge_id(challenge_id: str) -> str:
    for suffix in MODE_SUFFIXES:
        if challenge_id.endswith(suffix):
            return challenge_id[: -len(suffix)]
    return challenge_id


def challenge_entries(listing: dict[str, Any]) -> list[dict[str, Any]]:
    challenges = listing.get("challenges")
    if not isinstance(challenges, list):
        raise AgentError("The documented Game Master list response has no challenges array")
    return [item for item in challenges if isinstance(item, dict) and item.get("id")]


def challenge_modes(
    base_id: str, entries: list[dict[str, Any]]
) -> list[tuple[str, dict[str, Any]]]:
    by_id = {str(item["id"]): item for item in entries}
    result = []
    for mode in MODE_ORDER:
        identifier = mode_id(base_id, mode)
        item = by_id.get(identifier)
        if item is not None:
            result.append((mode, item))
    return result


def notes_path(base_id: str) -> pathlib.Path:
    return NOTES_DIR / f"{safe_component(base_id)}.md"


def already_handed_back(base_id: str, state: dict[str, Any]) -> bool:
    if base_id in state.get("handed_back", []):
        return True
    path = notes_path(base_id)
    try:
        return "## Handed back" in path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False


def first_incomplete(
    entries: list[dict[str, Any]], state: dict[str, Any], *, min_day: int = 1
) -> str | None:
    bases = []
    seen = set()
    for item in entries:
        challenge_id = str(item["id"])
        base_id = base_challenge_id(challenge_id)
        if base_id in seen or already_handed_back(base_id, state):
            continue
        seen.add(base_id)
        modes = challenge_modes(base_id, entries)
        if any(item.get("solved") is not True for _, item in modes):
            try:
                day = int(item.get("day", 999))
            except (TypeError, ValueError):
                day = 999
            if day < min_day:
                continue
            bases.append((day, len(bases), base_id))
    bases.sort()
    return bases[0][2] if bases else None


def registry_entries() -> list[dict[str, Any]]:
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        entries = data["solvers"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AgentError(f"Could not read solver registry {REGISTRY_PATH}") from exc
    if not isinstance(entries, list):
        raise AgentError("Registry field 'solvers' must be an array")
    return [item for item in entries if isinstance(item, dict)]


def mark_mode_passed(
    solver_name: str,
    mode: str,
    solver_hash: str | None = None,
) -> None:
    try:
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        entries = registry["solvers"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise AgentError("Could not update the solver registry") from exc
    solver = next(
        (
            item
            for item in entries
            if isinstance(item, dict) and item.get("name") == solver_name
        ),
        None,
    )
    if solver is None:
        raise AgentError(f"Solver {solver_name!r} disappeared from the registry")
    modes_passed = solver.setdefault("modes_passed", [])
    changed = False
    if mode not in modes_passed:
        modes_passed.append(mode)
        modes_passed.sort(key=lambda value: MODE_ORDER.index(value) if value in MODE_ORDER else 999)
        changed = True
    if mode == "single_solve" and solver_hash:
        if solver.get("approved_solver_sha256") != solver_hash:
            solver["approved_solver_sha256"] = solver_hash
            changed = True
        snapshot = AGENT_DIR / "approved_solvers" / (
            f"{safe_component(solver_name)}-{solver_hash}.py"
        )
        current_source = ROOT / str(solver["path"])
        if current_source.is_file():
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            if not snapshot.exists():
                snapshot.write_bytes(current_source.read_bytes())
            relative_snapshot = str(snapshot.relative_to(ROOT))
            if solver.get("approved_source") != relative_snapshot:
                solver["approved_source"] = relative_snapshot
                changed = True
    if changed:
        write_json(REGISTRY_PATH, registry)


def solver_hash_review_required(spec: dict[str, Any], solver_hash: str) -> bool:
    """Changed solver code must be reviewed offline before a timed start."""
    return spec.get("approved_solver_sha256") != solver_hash


def timed_auto_submit_allowed(spec: dict[str, Any], solver_hash: str) -> bool:
    """Timed submission is automatic only for the reviewed source hash."""
    return not solver_hash_review_required(spec, solver_hash)


def semantic_field(answer_id: str, question: dict[str, Any]) -> str:
    _, parsed = parse_answer_id(answer_id)
    text = str(question.get("question", "")).lower()
    if "lnk-target-path-windows" in parsed.lower() or "lnk.target_path_windows" in text:
        return "lnk.target_path_windows"
    if "mvid" in parsed.lower() or "module version id" in text:
        return "dotnet_mvid_guid"
    if "msi-product-code-guid" in parsed.lower() or "msi.product_code_guid" in text:
        return "msi_product_code_guid"
    if "pe.coff_machine_u16_hex" in text or "pe-coff-machine-u16-hex" in parsed.lower():
        return "pe_coff_machine_u16_hex"
    if "pe.address_of_entry_point_rva_hex" in text or "pe-address-of-entry-point-rva-hex" in parsed.lower():
        return "pe_address_of_entry_point_rva_hex"
    if "png.ihdr_dimensions_pixels" in text or "png-ihdr-dimensions-pixels" in parsed.lower():
        return "png_ihdr_dimensions_pixels"
    if "import" in parsed.lower() or "import" in text:
        return "imports"
    if (
        "utf8-bom-present" in answer_id.lower()
        or "utf8_bom_present" in text
        or ("utf-8" in text and "bom" in text and "present" in text)
    ):
        return "utf8_bom_present"
    if "prefix" in parsed or ("first" in text and "bytes" in text):
        return "prefix_hex"
    if "sha-256" in text or "sha256" in parsed:
        return "sha256"
    if "sha-1" in text or "sha1" in parsed:
        return "sha1"
    if "md5" in text or parsed.endswith("md5"):
        return "md5"
    if "filename" in text:
        if "first exact filename" in text:
            return "collection-file"
        if "recovery-note" in text:
            return "impact-note"
        return "filename"
    if "size in bytes" in text:
        return "size_bytes"
    if "mitre" in text or "technique id" in text:
        return parsed.removesuffix("-attack") + "-attack" if "-" in parsed else "attack"
    if "scenario" in text:
        return parsed
    if "user-agent" in text:
        return "collection-user-agent"
    return parsed


def choose_solver(
    base_id: str,
    start: dict[str, Any],
    entries: list[dict[str, Any]],
) -> tuple[dict[str, Any], float]:
    candidates = [
        item
        for item in entries
        if base_id in item.get("challenge_ids", [])
    ]
    if not candidates:
        raise AgentError("No registered solver covers this challenge ID")
    if len(candidates) > 1:
        raise AgentError("Registry has multiple solvers for this challenge ID")

    spec = candidates[0]
    answer_ids = start.get("answer_ids")
    if not isinstance(answer_ids, list) or not answer_ids:
        raise AgentError("Active start response did not return answer_ids")
    questions = questions_by_id(start, answer_ids)
    declared = set(spec.get("question_fields", []))
    covered = [
        semantic_field(answer_id, question) in declared
        for answer_id, question in questions.items()
    ]
    coverage = sum(covered) / len(covered)
    return spec, coverage


def magic_description(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "ZIP"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP"
    if data.startswith(b"%PDF-"):
        return "PDF"
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return f"unknown ({data[:8].hex()})"
    return "UTF-8 text"


def inspect_static_contents(
    data: bytes,
    label: str = "artifact",
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Identify ZIP members from bytes without extracting or executing them."""
    if budget is None:
        budget = [128, 64 * 1024 * 1024]
    records = [{"path": label, "bytes": len(data), "magic_type": magic_description(data)}]
    if depth >= 5 or not zipfile.is_zipfile(io.BytesIO(data)):
        return records

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            for index, info in enumerate(infos):
                member_label = f"{label}/member[{index}]"
                record = {
                    "path": member_label,
                    "bytes": info.file_size,
                    "magic_type": "unreadable",
                }
                records.append(record)
                budget[0] -= 1
                if budget[0] < 0:
                    record["magic_type"] = "inspection member limit reached"
                    break
                if info.file_size > 16 * 1024 * 1024 or info.file_size > budget[1]:
                    record["magic_type"] = "inspection size limit reached"
                    continue
                try:
                    member_data = archive.read(info)
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    record["magic_type"] = "encrypted or unreadable"
                    continue
                budget[1] -= len(member_data)
                record["magic_type"] = magic_description(member_data)
                if zipfile.is_zipfile(io.BytesIO(member_data)):
                    records.extend(
                        inspect_static_contents(
                            member_data,
                            member_label,
                            depth=depth + 1,
                            budget=budget,
                        )[1:]
                    )
                if budget[1] <= 0:
                    break
    except (OSError, zipfile.BadZipFile):
        pass
    return records


def sensitive_answer(answer_id: str, question: dict[str, Any]) -> bool:
    _, field = parse_answer_id(answer_id)
    text = f"{field} {question.get('question', '')}".casefold()
    return "flag" in text or "proof" in text


def display_answers(
    answers: dict[str, str],
    reasoning: dict[str, str],
    questions: dict[str, dict[str, Any]],
) -> None:
    print("Dry-run answers and evidence:")
    for answer_id, answer in answers.items():
        sensitive = sensitive_answer(answer_id, questions[answer_id])
        if sensitive:
            shown = "[stored privately]"
        else:
            shown = answer
        print(f"- {answer_id}: {safe_public_text(shown)}")
        explanation = (
            "[private answer evidence withheld]"
            if sensitive
            else safe_public_text(reasoning.get(answer_id, "No reasoning returned."))
        )
        print(f"  Reasoning: {explanation}")


def record_sensitive_answers(
    client: GMClient,
    challenge_id: str,
    answers: dict[str, str],
    questions: dict[str, dict[str, Any]],
) -> set[str]:
    stored = set()
    for answer_id, value in answers.items():
        if sensitive_answer(answer_id, questions[answer_id]):
            register_private_value(value)
            client.store_private_flag(f"{challenge_id}:target", value)
            stored.add(answer_id)
    return stored


def write_handoff(
    base_id: str,
    name: str,
    lane: str,
    reason: str,
    done: str,
    action_needed: str,
    resume: str,
    state: dict[str, Any],
    log_path: pathlib.Path,
) -> None:
    path = notes_path(base_id)
    previous = ""
    try:
        previous = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        pass
    if "## Handed back" in previous:
        previous = previous.split("## Handed back", 1)[0].rstrip()
    content = previous or (
        f"# {name}\n\n"
        f"- **Challenge ID:** `{base_id}`\n"
        f"- **Category:** {lane or 'unknown'}\n"
        f"- **Summary:** Automated solver could not safely complete this challenge.\n"
    )
    content += (
        "\n\n## Handed back\n\n"
        f"- **What's done:** {done}\n"
        f"- **What's blocking it:** {reason}\n"
        f"- **What I need you to do:** {action_needed}\n"
        f"- **How to resume:** {resume}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(safe_public_text(content), encoding="utf-8")
    returned = state.setdefault("handed_back", [])
    if base_id not in returned:
        returned.append(base_id)
    write_json(STATE_PATH, state, private=True)
    log_event(
        log_path,
        {
            "action": "handback",
            "challenge": base_id,
            "reason": reason,
            "note": str(path.relative_to(ROOT)),
        },
    )


def solver_python() -> pathlib.Path:
    return configured_python()


def run_solver(
    spec: dict[str, Any],
    start_path: pathlib.Path,
    artifact_paths: list[pathlib.Path],
) -> tuple[dict[str, str], dict[str, str], bool]:
    solver_path = ROOT / str(spec.get("path", ""))
    if not solver_path.is_file():
        raise AgentError(f"Registered solver is missing: {spec.get('path')}")
    module = ".".join(solver_path.relative_to(ROOT).with_suffix("").parts)
    command = [
        str(solver_python()),
        "-m",
        module,
        "--start",
        str(start_path),
    ]
    for artifact_path in artifact_paths:
        command.extend(("--artifact", str(artifact_path)))
    command.append("--dry-run")
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise AgentError("Solver exceeded the 20-second analysis limit") from exc
    if result.returncode != 0:
        try:
            error = json.loads(result.stderr).get("error")
        except (json.JSONDecodeError, AttributeError):
            error = "solver returned an unstructured error"
        message = str(error or "solver failed")
        if "not installed" in message.lower() and "requires" in message.lower():
            raise DependencyRequired(safe_public_text(message))
        raise AgentError(safe_public_text(message))
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AgentError("Solver dry-run did not return JSON") from exc
    answers = output.get("answers")
    reasoning = output.get("reasoning")
    replay = output.get("replay")
    if not isinstance(answers, dict) or not isinstance(reasoning, dict):
        raise AgentError("Solver dry-run omitted answers or reasoning")
    return (
        {str(key): str(value) for key, value in answers.items()},
        {str(key): str(value) for key, value in reasoning.items()},
        bool(replay),
    )


def validate_answers(
    start: dict[str, Any],
    answers: dict[str, str],
    reasoning: dict[str, str],
) -> dict[str, dict[str, Any]]:
    answer_ids = start.get("answer_ids")
    if not isinstance(answer_ids, list) or set(answers) != set(answer_ids):
        raise AgentError("Solver answer keys do not exactly match this attempt's answer_ids")
    questions = questions_by_id(start, answer_ids)
    if set(reasoning) != set(answer_ids):
        raise AgentError("Solver reasoning does not cover every returned answer_id")
    for answer_id in answer_ids:
        validate_answer_format(answer_id, answers[answer_id], questions[answer_id])
    return questions


def artifact_folder(base_id: str, attempt_id: str) -> pathlib.Path:
    return ARTIFACTS_DIR / safe_component(base_id) / safe_component(attempt_id)


def save_start_and_artifacts(
    client: GMClient,
    challenge_id: str,
    base_id: str,
    mode: str,
    start: dict[str, Any],
) -> tuple[pathlib.Path, list[pathlib.Path], list[dict[str, Any]]]:
    attempt_id = start.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise AgentError("Active start response did not return attempt_id")
    folder = artifact_folder(base_id, attempt_id)
    folder.mkdir(parents=True, exist_ok=True)
    start_path = folder / "start.json"
    write_json(start_path, start)

    # Web exploitation attempts provide live targets in the start response and
    # do not have downloadable artifact bytes.
    targets = start.get("targets")
    if isinstance(targets, list) and targets:
        if base_id != "web-exploitation-day-09-forged-with-care":
            raise AgentError(
                "No reviewed target collector is registered for this Web challenge"
            )
        from agent.target_capture import (
            TargetCaptureError,
            capture_assigned_targets,
            target_marker,
        )

        try:
            proofs, target_records = capture_assigned_targets(start)
        except TargetCaptureError as exc:
            raise AgentError(str(exc)) from exc
        for target_id, proof in proofs.items():
            register_private_value(proof)
            client.store_private_flag(
                f"target-proof:{start['attempt_id']}:{target_id}",
                proof,
            )
        marker_path = folder / "artifact-00.bin"
        marker = target_marker(str(start["attempt_id"]), target_records)
        marker_path.write_bytes(marker)
        artifact_record = {
            "path": str(marker_path.relative_to(ROOT)),
            "bytes": len(marker),
            "sha256": sha256_bytes(marker),
            "magic_type": "private target evidence marker",
            "delivery": None,
            "inventory": [
                {
                    "path": str(target.get("target_id", "")),
                    "bytes": int(target.get("proof_length", 0)),
                    "sha256": "stored in private flags file",
                    "magic_type": "verified target evidence",
                }
                for target in target_records
            ],
        }
        return start_path, [marker_path], [artifact_record]

    deliveries = delivery_indexes(start) if mode == "mastery" else []
    delivery_indexes_to_fetch: list[int | None] = deliveries or [None]
    artifact_paths = []
    artifact_records = []
    for number, delivery in enumerate(delivery_indexes_to_fetch):
        data = client.artifact(challenge_id, delivery=delivery)
        artifact_path = folder / f"artifact-{number:02d}.bin"
        artifact_path.write_bytes(data)
        artifact_paths.append(artifact_path)
        artifact_records.append(
            {
                "path": str(artifact_path.relative_to(ROOT)),
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "magic_type": magic_description(data),
                "delivery": delivery,
                "inventory": inspect_static_contents(data),
            }
        )
    return start_path, artifact_paths, artifact_records


def mode_submission_key(challenge_id: str, attempt_id: str) -> str:
    # The cap applies to this challenge mode across expired-attempt retries.
    return challenge_id


def check_submission_policy(
    state: dict[str, Any],
    challenge_id: str,
    attempt_id: str,
    answer_hash: str,
    solver_hash: str,
    diagnosis: str | None,
) -> dict[str, Any]:
    key = mode_submission_key(challenge_id, attempt_id)
    entries = state.setdefault("submissions", {})
    prior = entries.get(key, {"count": 0})
    count = int(prior.get("count", 0))
    if prior.get("last_result") in {"submission_in_flight", "response_unknown"}:
        raise SubmissionUncertain(
            "A previous submission may have reached the Game Master; resume and check the same attempt before sending another"
        )
    if count >= 3:
        raise SubmissionLimitReached("submission limit reached (3)")
    if count > 0:
        if not diagnosis or len(diagnosis.strip()) < 20:
            raise SubmissionPolicyError(
                "resubmission requires a written diagnosis of what was wrong and what changed"
            )
        changed = (
            answer_hash != prior.get("answer_hash")
            or solver_hash != prior.get("solver_hash")
        )
        if not changed:
            raise SubmissionPolicyError(
                "answers and solver are unchanged since the last submission"
            )
    return prior


def deadline_has_passed(start: dict[str, Any]) -> bool:
    deadline = start.get("deadline")
    if not isinstance(deadline, str) or not deadline:
        return False
    try:
        expires = dt.datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AgentError("Game Master returned an invalid deadline") from exc
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.timezone.utc)
    return expires <= dt.datetime.now(dt.timezone.utc)


def write_challenge_note(
    base_id: str,
    listing_entry: dict[str, Any],
    status_rows: list[dict[str, Any]],
    artifact_records: list[dict[str, Any]],
    solver_name: str | None,
    handoff: dict[str, str] | None = None,
) -> None:
    note = notes_path(base_id)
    name = str(listing_entry.get("name", base_id))
    lane = str(listing_entry.get("lane", "unknown"))
    prompt = str(listing_entry.get("prompt", "")).strip()
    content = [
        f"# {name}",
        "",
        f"- **Challenge ID:** `{base_id}`",
        f"- **Category:** {lane}",
        f"- **Summary:** {prompt or 'See the Game Master start response saved under the attempt artifact folder.'}",
        "",
        "## Artifact",
        "",
    ]
    if artifact_records:
        for item in artifact_records:
            content.append(
                f"- `{item['path']}` — {item['magic_type']}, {item['bytes']} bytes, "
                f"SHA-256 `{item['sha256']}`"
            )
    else:
        content.append("- No artifact was downloaded.")
    content.extend(
        [
            "",
            "## How the solver works",
            "",
            f"Static solver: `{solver_name or 'none'}`. It reads the assigned bytes and derives answers from the returned questions; challenge binaries and scripts are not executed.",
            "",
            "## Variants seen",
            "",
            "- See the saved start response and artifact records for this run.",
            "",
            "## Gotchas",
            "",
            "- Answer fields and formats come from the current attempt response.",
            "",
            "## Status per mode",
            "",
        ]
    )
    for row in status_rows:
        content.append(
            f"- `{row['mode']}`: **{row['result']}**, submissions {row['submissions']}"
        )
    if handoff:
        content.extend(
            [
                "",
                "## Handed back",
                "",
                f"- **What's done:** {handoff['done']}",
                f"- **What's blocking it:** {handoff['reason']}",
                f"- **What I need you to do:** {handoff['action_needed']}",
                f"- **How to resume:** {handoff['resume']}",
            ]
        )
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text(safe_public_text("\n".join(content) + "\n"), encoding="utf-8")


def append_timed_review_note(base_id: str, mode: str, result: str) -> None:
    path = notes_path(base_id)
    content = (
        "\n## Timed mode review required\n\n"
        f"- **Mode result:** {result}\n"
        "- **Proposed fix:** Review the saved artifact and dry-run evidence, including the "
        "decode, final-line extraction, delivery mapping, and answer format. Change the solver "
        "only after user approval; do not resubmit automatically.\n"
    )
    with path.open("a", encoding="utf-8") as note:
        note.write(safe_public_text(content))


def process_mode(
    client: GMClient,
    base_id: str,
    mode: str,
    list_entry: dict[str, Any],
    solver_entries: list[dict[str, Any]],
    state: dict[str, Any],
    args: argparse.Namespace,
    supervised: bool,
    log_path: pathlib.Path,
    prepared_start: dict[str, Any] | None = None,
) -> dict[str, Any]:
    challenge_id = mode_id(base_id, mode)
    timed = mode in TIMED_MODES
    run_for_time = (
        True if timed and list_entry.get("run_for_time_supported") is True else None
    )
    start = prepared_start or client.start_or_retry_expired(
        challenge_id, timed=timed, run_for_time=run_for_time
    )
    if start.get("result") == "CORRECT":
        row = {
            "mode": mode,
            "result": "already CORRECT",
            "submissions": 0,
            "solver": None,
        }
        log_event(log_path, {"action": "mode_already_solved", "challenge": challenge_id})
        return row

    spec, coverage = choose_solver(base_id, start, solver_entries)
    if coverage < 0.70:
        raise AgentError(
            f"Registered solver covers only {coverage:.0%} of this attempt's question fields"
        )
    start_path, artifact_paths, artifact_records = save_start_and_artifacts(
        client, challenge_id, base_id, mode, start
    )
    log_event(
        log_path,
        {
            "action": "artifacts_downloaded",
            "challenge": challenge_id,
            "attempt_id": start.get("attempt_id"),
            "artifacts": artifact_records,
        },
    )
    answers, reasoning, replay = run_solver(spec, start_path, artifact_paths)
    if replay:
        raise AgentError(
            "A completed replay was returned where an active attempt was required; no submission sent"
        )
    questions = validate_answers(start, answers, reasoning)
    answer_hash = answer_fingerprint(answers)
    solver_path = ROOT / str(spec["path"])
    solver_hash = file_fingerprint(solver_path)
    sensitive_ids = record_sensitive_answers(
        client, challenge_id, answers, questions
    )
    safe_answers = {
        key: ("[stored privately]" if key in sensitive_ids else value)
        for key, value in answers.items()
    }
    dry_report = {
        "challenge": challenge_id,
        "attempt_id": start["attempt_id"],
        "solver": spec["name"],
        "replay": False,
        "answers": safe_answers,
        "reasoning": {
            key: (
                "[private answer evidence withheld]"
                if key in sensitive_ids
                else value
            )
            for key, value in reasoning.items()
        },
        "submissions": 0,
    }
    dry_report_path = RUNS_DIR / f"{timestamp()}-{safe_component(spec['name'])}-dryrun.json"
    write_json(dry_report_path, dry_report)
    log_event(
        log_path,
        {
            "action": "solver_dry_run",
            "challenge": challenge_id,
            "attempt_id": start["attempt_id"],
            "solver": spec["name"],
            "answer_count": len(answers),
            "answer_sha256": answer_hash,
            "report": str(dry_report_path.relative_to(ROOT)),
        },
    )
    print(
        f"\n{challenge_id} — {spec['name']} — {len(answers)} answers ready "
        f"({coverage:.0%} field coverage)"
    )
    display_answers(answers, reasoning, questions)

    if deadline_has_passed(start):
        log_event(
            log_path,
            {
                "action": "deadline_expired_before_submission",
                "challenge": challenge_id,
                "attempt_id": start["attempt_id"],
            },
        )
        return {
            "mode": mode,
            "result": "deadline expired before submission",
            "submissions": 0,
            "solver": spec["name"],
            "artifacts": artifact_records,
        }

    prior = check_submission_policy(
        state,
        challenge_id,
        str(start["attempt_id"]),
        answer_hash,
        solver_hash,
        args.diagnosis,
    )
    if timed and not timed_auto_submit_allowed(spec, solver_hash):
        raise AgentError(
            "Solver hash changed after the timed preflight. No submission was sent; "
            "stop and review offline before starting another timed attempt."
        )
    if not timed and supervised:
        try:
            approval = input("Type 'submit' to send these answers, or press Enter to stop: ")
        except EOFError:
            approval = ""
        if approval.strip() != "submit":
            log_event(
                log_path,
                {
                    "action": "submission_paused",
                    "challenge": challenge_id,
                    "attempt_id": start["attempt_id"],
                },
            )
            return {
                "mode": mode,
                "result": "paused before submission",
                "submissions": 0,
                "solver": spec["name"],
                "artifacts": artifact_records,
            }

    key = mode_submission_key(challenge_id, str(start["attempt_id"]))
    submissions = state.setdefault("submissions", {})
    prior_count = int(prior.get("count", 0))
    submissions[key] = {
        "count": prior_count + 1,
        "answer_hash": answer_hash,
        "solver_hash": solver_hash,
        "attempt_id": start["attempt_id"],
        "last_result": "submission_in_flight",
    }
    write_json(STATE_PATH, state, private=True)
    log_event(
        log_path,
        {
            "action": "submission_started",
            "challenge": challenge_id,
            "attempt_id": start["attempt_id"],
            "submission_number": prior_count + 1,
            "answer_sha256": answer_hash,
        },
    )
    try:
        result = client.submit(challenge_id, answers)
    except Exception as exc:
        submissions[key]["last_result"] = "response_unknown"
        write_json(STATE_PATH, state, private=True)
        log_event(
            log_path,
            {
                "action": "submission_response_unknown",
                "challenge": challenge_id,
                "attempt_id": start["attempt_id"],
                "exception_type": type(exc).__name__,
            },
        )
        raise SubmissionUncertain(
            "submission response was lost or unclear; resume the same attempt and check its status before sending another"
        ) from exc
    submissions[key]["last_result"] = result.get("result")
    write_json(STATE_PATH, state, private=True)
    row = {
        "mode": mode,
        "result": result.get("result", "unknown"),
        "submissions": prior_count + 1,
        "solver": spec["name"],
        "artifacts": artifact_records,
    }
    if result.get("status") == "pending":
        row["status"] = "pending"
    log_event(
        log_path,
        {
            "action": "submission",
            "challenge": challenge_id,
            "attempt_id": start["attempt_id"],
            "result": row["result"],
            "status": row.get("status"),
            "submission_number": prior_count + 1,
            "answer_sha256": answer_hash,
        },
    )
    if row["result"] == "CORRECT":
        mark_mode_passed(spec["name"], mode, solver_hash)
        if mode == "single_solve":
            spec["approved_solver_sha256"] = solver_hash
        pending = " (scoring pending)" if row.get("status") == "pending" else ""
        print(f"{challenge_id} {mode}: CORRECT{pending}; flag received")
    else:
        print(f"{challenge_id} {mode}: {row['result']}")
        if timed:
            print(
                "Timed mode stopped for review. Proposed fix: inspect the saved fresh artifact, "
                "decoded final line, delivery mapping, and format check; do not change or "
                "resubmit the solver until you approve a specific fix."
            )
    return row


def run_challenge(
    client: GMClient,
    base_id: str,
    entries: list[dict[str, Any]],
    solver_entries: list[dict[str, Any]],
    state: dict[str, Any],
    args: argparse.Namespace,
    supervised: bool,
    log_path: pathlib.Path,
    started_clock: float,
) -> tuple[list[dict[str, Any]], bool]:
    modes = challenge_modes(base_id, entries)
    if not modes:
        raise AgentError("Challenge ID was not present in the documented list response")
    base_entry = next(
        (item for item in entries if str(item.get("id")) == base_id),
        modes[0][1],
    )
    name = str(base_entry.get("name", base_id))
    lane = str(base_entry.get("lane", "unknown"))
    rows: list[dict[str, Any]] = []
    artifact_records: list[dict[str, Any]] = []
    solver_name: str | None = None
    handoff = None
    any_unsolved = any(item.get("solved") is not True for _, item in modes)
    if not any_unsolved:
        return (
            [
                {
                    "challenge": base_id,
                    "mode": mode,
                    "result": "already CORRECT",
                    "submissions": 0,
                    "solver": None,
                }
                for mode, _ in modes
            ],
            False,
        )

    unsolved_timed = [
        (mode, item)
        for mode, item in modes
        if mode in TIMED_MODES and item.get("solved") is not True
    ]
    single_solve_passed = any(
        mode == "single_solve" and item.get("solved") is True
        for mode, item in modes
    )
    if unsolved_timed and single_solve_passed:
        registered = [
            item
            for item in solver_entries
            if base_id in item.get("challenge_ids", [])
        ]
        if len(registered) == 1:
            spec = registered[0]
            solver_path = ROOT / str(spec.get("path", ""))
            current_hash = file_fingerprint(solver_path)
            if solver_hash_review_required(spec, current_hash):
                from agent.solver_review import print_offline_review

                report = print_offline_review(str(spec["name"]))
                log_event(
                    log_path,
                    {
                        "action": "solver_hash_review_required",
                        "challenge": base_id,
                        "solver": spec["name"],
                        "current_solver_sha256": current_hash,
                        "report": str(report.relative_to(ROOT)),
                        "timed_start": "not_started",
                    },
                )
                return (
                    [
                        {
                            "challenge": base_id,
                            "mode": unsolved_timed[0][0],
                            "result": "offline solver review required before timed start",
                            "submissions": 0,
                            "solver": spec["name"],
                            "review": str(report.relative_to(ROOT)),
                        }
                    ],
                    False,
                )

    if not any(base_id in item.get("challenge_ids", []) for item in solver_entries):
        single_solve = next(
            ((mode, item) for mode, item in modes if mode == "single_solve"),
            None,
        )
        artifacts = []
        if single_solve:
            start = client.start_or_retry_expired(base_id, timed=False)
            if start.get("result") != "CORRECT":
                start_path, artifact_paths, artifacts = save_start_and_artifacts(
                    client,
                    base_id,
                    base_id,
                    "single_solve",
                    start,
                )
                log_event(
                    log_path,
                    {
                        "action": "unsupported_challenge_single_saved",
                        "challenge": base_id,
                        "attempt_id": start.get("attempt_id"),
                        "start": str(start_path.relative_to(ROOT)),
                        "artifacts": artifacts,
                        "submissions": 0,
                    },
                )
        reason = "No registered solver covers this challenge family."
        done = (
            "The Single Solve response and assigned artifact were saved locally."
            if artifacts
            else "The challenge was found, but no unsolved Single Solve artifact was available to capture."
        )
        action = (
            "Review the saved questions and artifact, develop a static solver for this family, "
            "and add it to the registry."
        )
        resume = f"Run `python3 agent/ctf_agent.py --challenge {base_id}` after adding the solver."
        if args.autonomous:
            log_event(
                log_path,
                {
                    "action": "solver_development_required",
                    "challenge": base_id,
                    "attempt_id": start.get("attempt_id") if single_solve else None,
                    "artifact_saved": bool(artifacts),
                    "submissions": 0,
                },
            )
            return (
                [
                    {
                        "challenge": base_id,
                        "mode": "selection",
                        "result": "solver development required before submission",
                        "submissions": 0,
                        "solver": None,
                        "pause_run": True,
                    }
                ],
                False,
            )
        write_handoff(
            base_id,
            name,
            lane,
            reason,
            done,
            action,
            resume,
            state,
            log_path,
        )
        return (
            [
                {
                    "challenge": base_id,
                    "mode": "selection",
                    "result": "handed back",
                    "submissions": 0,
                    "solver": None,
                    "handoff": str(notes_path(base_id).relative_to(ROOT)),
                }
            ],
            True,
        )

    try:
        for mode, item in modes:
            if item.get("solved") is True:
                rows.append(
                    {
                        "challenge": base_id,
                        "mode": mode,
                        "result": "already CORRECT",
                        "submissions": 0,
                        "solver": None,
                    }
                )
                continue
            previous = state.get("submissions", {}).get(mode_id(base_id, mode), {})
            if previous.get("last_result") in {
                "submission_in_flight",
                "response_unknown",
            }:
                raise SubmissionUncertain(
                    f"{mode} has a submission with an unknown outcome; inspect the same attempt before resuming"
                )
            if int(previous.get("count", 0)) >= 3:
                reason = "The mode reached its three-submission limit."
                write_handoff(
                    base_id,
                    name,
                    lane,
                    reason,
                    f"{mode} already has three recorded submissions.",
                    "Review the saved attempts and continue manually without another automated submission.",
                    "Continue with the next challenge; this mode must not receive another submission.",
                    state,
                    log_path,
                )
                rows.append(
                    {
                        "challenge": base_id,
                        "mode": mode,
                        "result": "handed back: submission limit reached",
                        "submissions": 0,
                        "solver": solver_name,
                        "handoff": str(notes_path(base_id).relative_to(ROOT)),
                    }
                )
                return rows, True
            if (time.monotonic() - started_clock) >= args.max_minutes * 60:
                rows.append(
                    {
                        "challenge": base_id,
                        "mode": mode,
                        "result": "run time limit reached",
                        "submissions": 0,
                        "solver": solver_name,
                    }
                )
                break
            try:
                row = process_mode(
                    client,
                    base_id,
                    mode,
                    item,
                    solver_entries,
                    state,
                    args,
                    supervised,
                    log_path,
                )
            except (DependencyRequired, SubmissionUncertain):
                raise
            except SubmissionLimitReached as exc:
                handoff = {
                    "done": "The solver produced answers, but the submission limit was reached.",
                    "reason": str(exc),
                    "action_needed": "Review the attempt and decide manually how to proceed.",
                    "resume": "Do not submit again for this mode; continue with the next challenge.",
                }
                write_handoff(
                    base_id,
                    name,
                    lane,
                    handoff["reason"],
                    handoff["done"],
                    handoff["action_needed"],
                    handoff["resume"],
                    state,
                    log_path,
                )
                rows.append(
                    {
                        "challenge": base_id,
                        "mode": mode,
                        "result": "handed back: " + str(exc),
                        "submissions": 0,
                        "solver": solver_name,
                        "handoff": str(notes_path(base_id).relative_to(ROOT)),
                    }
                )
                return rows, True
            except SubmissionPolicyError as exc:
                rows.append(
                    {
                        "challenge": base_id,
                        "mode": mode,
                        "result": "paused: " + str(exc),
                        "submissions": 0,
                        "solver": solver_name,
                    }
                )
                write_challenge_note(
                    base_id,
                    base_entry,
                    [
                        {
                            "mode": item["mode"],
                            "result": item["result"],
                            "submissions": item["submissions"],
                        }
                        for item in rows
                    ],
                    artifact_records,
                    solver_name,
                )
                return rows, False
            except AgentError as exc:
                action_needed = (
                    "Review the saved start response, artifact, solver error, and answer formats; "
                    "then provide or update the solver before resuming."
                )
                handoff = {
                    "done": "The current attempt response and any downloaded artifacts are saved locally.",
                    "reason": str(exc),
                    "action_needed": action_needed,
                    "resume": f"Run `python3 agent/ctf_agent.py --challenge {base_id}` after addressing the blocker.",
                }
                write_handoff(
                    base_id,
                    name,
                    lane,
                    handoff["reason"],
                    handoff["done"],
                    handoff["action_needed"],
                    handoff["resume"],
                    state,
                    log_path,
                )
                rows.append(
                    {
                        "challenge": base_id,
                        "mode": mode,
                        "result": "handed back",
                        "submissions": 0,
                        "solver": solver_name,
                        "handoff": str(notes_path(base_id).relative_to(ROOT)),
                    }
                )
                return rows, True
            rows.append(
                {
                    "challenge": base_id,
                    **row,
                }
            )
            solver_name = row.get("solver") or solver_name
            artifact_records.extend(row.get("artifacts", []))
            if row.get("result") == "paused before submission":
                break
            if row.get("result") not in {"CORRECT", "already CORRECT"}:
                write_challenge_note(
                    base_id,
                    base_entry,
                    [
                        {
                            "mode": item["mode"],
                            "result": item["result"],
                            "submissions": item["submissions"],
                        }
                        for item in rows
                    ],
                    artifact_records,
                    solver_name,
                )
                if row.get("submissions", 0) >= 3:
                    reason = "The mode reached its three-submission limit."
                    write_handoff(
                        base_id,
                        name,
                        lane,
                        reason,
                        f"{mode} received {row.get('result')} after three submissions.",
                        "Review the saved attempts and continue manually without another automated submission.",
                        "Continue with the next challenge; this mode must not receive another submission.",
                        state,
                        log_path,
                    )
                    rows[-1]["result"] = "handed back: submission limit reached"
                    rows[-1]["handoff"] = str(notes_path(base_id).relative_to(ROOT))
                    return rows, True
                if mode in TIMED_MODES and row.get("submissions", 0):
                    append_timed_review_note(base_id, mode, str(row.get("result")))
                    rows[-1]["result"] = f"{row.get('result')} (paused for review)"
                    rows[-1]["pause_run"] = True
                    log_event(
                        log_path,
                        {
                            "action": "timed_mode_review_required",
                            "challenge": mode_id(base_id, mode),
                            "result": row.get("result"),
                            "submissions": row.get("submissions"),
                        },
                    )
                    return rows, False
                if row.get("submissions", 0):
                    log_event(
                        log_path,
                        {
                            "action": "awaiting_diagnosis",
                            "challenge": mode_id(base_id, mode),
                            "result": row.get("result"),
                            "submissions": row.get("submissions"),
                        },
                    )
                return rows, False
        write_challenge_note(
            base_id,
            base_entry,
            [
                {"mode": row["mode"], "result": row["result"], "submissions": row["submissions"]}
                for row in rows
            ],
            artifact_records,
            solver_name,
            handoff,
        )
        return rows, False
    except Exception:
        raise


def print_summary(rows: list[dict[str, Any]], elapsed: float) -> None:
    headers = ("Challenge", "Mode", "Result", "Submissions", "Time", "Solver / handoff")
    table = [headers]
    for row in rows:
        solver = str(row.get("solver") or "")
        if row.get("handoff"):
            solver = f"handoff: {row['handoff']}"
        table.append(
            (
                str(row.get("challenge", "")),
                str(row.get("mode", "")),
                str(row.get("result", "")),
                str(row.get("submissions", 0)),
                f"{elapsed:.1f}s",
                solver,
            )
        )
    widths = [max(len(line[index]) for line in table) for index in range(len(headers))]
    for index, line in enumerate(table):
        print(
            " | ".join(
                safe_public_text(value).ljust(widths[column])
                for column, value in enumerate(line)
            )
        )
        if index == 0:
            print("-+-".join("-" * width for width in widths))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run registered Huntress CTF artifact solvers through the supported Game Master proxy."
    )
    parser.add_argument("--challenge", help="run this challenge family by its base ID")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--supervised",
        action="store_true",
        help="pause before every submission (default)",
    )
    mode_group.add_argument(
        "--autonomous",
        action="store_true",
        help="submit solver-derived answers without prompting",
    )
    parser.add_argument("--diagnosis", help="required explanation for a resubmission")
    parser.add_argument("--max-challenges", type=int, default=3)
    parser.add_argument("--max-minutes", type=int, default=60)
    parser.add_argument("--from-day", type=int, default=1)
    args = parser.parse_args()
    if args.max_challenges < 1 or args.max_minutes < 1 or args.from_day < 1:
        parser.error("--max-challenges, --max-minutes, and --from-day must be positive")

    supervised = not args.autonomous
    run_stamp = timestamp()
    log_path = RUNS_DIR / f"{run_stamp}.jsonl"
    started_clock = time.monotonic()
    elapsed_rows: list[dict[str, Any]] = []

    try:
        preflight = dependency_preflight()
        log_event(
            log_path,
            {
                "action": "environment_preflight",
                "passed": preflight["passed"],
                "python": preflight["python"],
                "requirements": preflight["requirements"],
                "system_tools": preflight["system_tools"],
                "errors": preflight["errors"],
            },
        )
        if not preflight["passed"]:
            print(
                "ctf_agent stopped before listing or starting challenges: "
                + format_preflight_errors(preflight),
                file=sys.stderr,
            )
            print(f"Run log: {log_path.relative_to(ROOT)}")
            return 2

        state = read_state()
        client = GMClient(event_sink=lambda event: log_event(log_path, event))
        listing = client.list_challenges(all_released=True)
        entries = challenge_entries(listing)
        solver_entries = registry_entries()
        log_event(
            log_path,
            {
                "action": "challenge_listed",
                "count": len(entries),
                "mode": "supervised" if supervised else "autonomous",
            },
        )

        if args.challenge:
            base_id = base_challenge_id(args.challenge)
            if base_id != args.challenge:
                raise AgentError("--challenge expects the base challenge ID without a mode suffix")
            selected = [base_id]
            handed_back = state.setdefault("handed_back", [])
            if base_id in handed_back:
                handed_back.remove(base_id)
                write_json(STATE_PATH, state, private=True)
        else:
            selected = []
            next_id = first_incomplete(entries, state, min_day=args.from_day)
            if next_id:
                selected.append(next_id)

        processed = 0
        while selected and processed < args.max_challenges:
            base_id = selected.pop(0)
            if already_handed_back(base_id, state) and not args.challenge:
                continue
            if not any(
                str(item.get("id")) == base_id
                or str(item.get("id", "")).startswith(base_id + "/")
                for item in entries
            ):
                raise AgentError(f"Challenge {base_id!r} was not returned by Game Master list")
            before = time.monotonic()
            try:
                rows, was_handed_back = run_challenge(
                    client,
                    base_id,
                    entries,
                    solver_entries,
                    state,
                    args,
                    supervised,
                    log_path,
                    started_clock,
                )
            except (DependencyRequired, SubmissionUncertain) as exc:
                log_event(
                    log_path,
                    {
                        "action": "run_stopped_safely",
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                print(
                    f"ctf_agent stopped safely: {safe_public_text(str(exc))}",
                    file=sys.stderr,
                )
                print_summary(elapsed_rows, time.monotonic() - started_clock)
                print(f"Run log: {log_path.relative_to(ROOT)}")
                return 2
            except AgentError as exc:
                matching = next(
                    (
                        item
                        for item in entries
                        if base_challenge_id(str(item.get("id"))) == base_id
                    ),
                    {"name": base_id, "lane": "unknown"},
                )
                write_handoff(
                    base_id,
                    str(matching.get("name", base_id)),
                    str(matching.get("lane", "unknown")),
                    str(exc),
                    "No answer was submitted for the blocked mode.",
                    "Resolve the reported environment, solver, or API issue.",
                    f"Run `python3 agent/ctf_agent.py --challenge {base_id}` to resume.",
                    state,
                    log_path,
                )
                rows = [
                    {
                        "challenge": base_id,
                        "mode": "selection",
                        "result": "handed back",
                        "submissions": 0,
                        "solver": None,
                        "handoff": str(notes_path(base_id).relative_to(ROOT)),
                    }
                ]
                was_handed_back = True
            except Exception as exc:
                matching = next(
                    (
                        item
                        for item in entries
                        if base_challenge_id(str(item.get("id"))) == base_id
                    ),
                    {"name": base_id, "lane": "unknown"},
                )
                message = (
                    f"Unexpected {type(exc).__name__} while contacting the documented service "
                    "or processing its response."
                )
                write_handoff(
                    base_id,
                    str(matching.get("name", base_id)),
                    str(matching.get("lane", "unknown")),
                    message,
                    "No answer was submitted for the blocked mode.",
                    "Review the service response and local error, then decide how to resume.",
                    f"Run `python3 agent/ctf_agent.py --challenge {base_id}` after resolving the issue.",
                    state,
                    log_path,
                )
                rows = [
                    {
                        "challenge": base_id,
                        "mode": "selection",
                        "result": "handed back",
                        "submissions": 0,
                        "solver": None,
                        "handoff": str(notes_path(base_id).relative_to(ROOT)),
                    }
                ]
                was_handed_back = True
            elapsed_rows.extend(rows)
            processed += 1
            log_event(
                log_path,
                {
                    "action": "challenge_finished",
                    "challenge": base_id,
                    "elapsed_seconds": round(time.monotonic() - before, 3),
                    "handed_back": was_handed_back,
                },
            )
            if any(row.get("pause_run") for row in rows):
                break
            if args.challenge or processed >= args.max_challenges:
                break
            next_id = first_incomplete(entries, state, min_day=args.from_day)
            if not next_id or next_id == base_id:
                break
            selected.append(next_id)
            if (time.monotonic() - started_clock) >= args.max_minutes * 60:
                break
    except (AgentError, OSError, RuntimeError, ValueError) as exc:
        print(
            f"ctf_agent stopped safely: {safe_public_text(str(exc))}",
            file=sys.stderr,
        )
        log_event(
            log_path,
            {"action": "run_error", "error": safe_public_text(str(exc))},
        )
        return 2

    elapsed = time.monotonic() - started_clock
    print_summary(elapsed_rows, elapsed)
    print(f"Run log: {log_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        reexec_in_configured_environment()
    except RuntimeEnvironmentError as exc:
        print(f"ctf_agent stopped safely: {exc}", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
