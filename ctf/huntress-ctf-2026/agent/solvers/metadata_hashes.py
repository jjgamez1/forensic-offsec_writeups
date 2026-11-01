#!/usr/bin/env python3
"""Hash the evidence member named by the current Game Master questions."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from email import policy
from email.parser import BytesParser
from io import BytesIO
from typing import Any

from agent.solvers.common import (
    SolverError,
    answer_ids_and_replay,
    artifact_hint,
    hinted_member,
    iter_zip_files,
    load_artifacts,
    questions_by_id,
    run_cli,
    unique_by_hint,
    validate_answer_format,
)
from agent.solvers.jpeg_structure import jpeg_sof_dimensions
from agent.solvers.dotnet_mvid import mvid_guid
from agent.solvers.lnk_target_path import target_path as lnk_target_path
from agent.solvers.png_structure import png_ihdr_dimensions
from agent.solvers.pe_original_filename import original_filename
from agent.solvers.ooxml_external_targets import _external_targets
from agent.solvers.evtx_record_count import evtx_record_count


def read_archive_members(
    paths: list[pathlib.Path],
) -> list[list[tuple[str, bytes]]]:
    def collect(data: bytes, label: str, depth: int = 0) -> list[tuple[str, bytes]]:
        if depth > 8:
            raise SolverError("Nested ZIP depth exceeds the static inspection limit")
        try:
            with zipfile.ZipFile(BytesIO(data)) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                encrypted = any(info.flag_bits & 1 for info in infos)
        except zipfile.BadZipFile:
            return []
        if encrypted:
            raise SolverError("Encrypted nested ZIP members are unsupported")

        members: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = archive.read(info)
                member_label = f"{label}/{info.filename}"
                members.append((member_label, member))
                if member.startswith(b"PK\x03\x04"):
                    members.extend(collect(member, member_label, depth + 1))
        return members

    files = load_artifacts(paths)
    groups: list[list[tuple[str, bytes]]] = []
    for path, data in files:
        members = collect(data, path.name)
        if not members:
            members = list(iter_zip_files(data, path.name))
        groups.append(members)
    return groups


def zip_eocd_total_entries(data: bytes, label: str) -> int:
    """Read the total-entry count from a structurally valid ZIP EOCD record."""
    signature = b"PK\x05\x06"
    offset = data.rfind(signature)
    if offset < 0 or offset + 22 > len(data):
        raise SolverError(f"{label}: ZIP end-of-central-directory record is missing")
    comment_length = struct.unpack_from("<H", data, offset + 20)[0]
    if offset + 22 + comment_length != len(data):
        raise SolverError(f"{label}: ZIP EOCD comment length does not match the file")
    disk_number, central_disk, disk_entries, total_entries = struct.unpack_from(
        "<HHHH", data, offset + 4
    )
    if disk_number or central_disk or disk_entries != total_entries:
        raise SolverError(f"{label}: multi-disk ZIP entry counts are unsupported")
    return total_entries


def sqlite_page_size_bytes(data: bytes, label: str) -> int:
    if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
        raise SolverError(f"{label}: SQLite database header is missing or truncated")
    stored_size = int.from_bytes(data[16:18], "big")
    page_size = 65536 if stored_size == 1 else stored_size
    if (
        page_size < 512
        or page_size > 65536
        or page_size & (page_size - 1)
    ):
        raise SolverError(f"{label}: SQLite header has an invalid page size")
    return page_size


def jar_manifest_main_class(data: bytes, label: str) -> str:
    """Read the literal Main-Class attribute from a JAR manifest."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            manifests = [
                info
                for info in archive.infolist()
                if info.filename.upper() == "META-INF/MANIFEST.MF"
            ]
            if not manifests:
                return "none"
            if len(manifests) != 1:
                raise SolverError(f"{label}: JAR has multiple manifest files")
            manifest = archive.read(manifests[0]).decode("utf-8-sig")
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError) as exc:
        raise SolverError(f"{label}: assigned JAR could not be read statically") from exc

    logical_lines: list[str] = []
    for line in manifest.splitlines():
        if line.startswith(" ") and logical_lines:
            logical_lines[-1] += line[1:]
        else:
            logical_lines.append(line)
    values = [
        match.group(1).strip()
        for line in logical_lines
        if (match := re.match(r"(?i)^Main-Class\s*:\s*(.*)$", line))
    ]
    if len(values) > 1:
        raise SolverError(f"{label}: JAR manifest has multiple Main-Class attributes")
    return values[0] if values else "none"


def format_width_hex(value: int, answer_id: str) -> str:
    """Format a numeric hex answer using the width stated by its answer ID."""
    width_match = re.search(r"(?:^|[_-])u(16|32|64)(?:[_-]|$)", answer_id)
    if width_match:
        width = int(width_match.group(1)) // 4
    elif re.search(r"(?:^|[_-])rva(?:[_-]|$)", answer_id):
        width = 8
    else:
        raise SolverError(
            f"Cannot determine hexadecimal field width from answer ID: {answer_id}"
        )
    return f"0x{value:0{width}x}"


def msi_product_code(data: bytes, label: str) -> str:
    msidump = shutil.which("msidump")
    if msidump is None:
        raise SolverError(f"{label}: msidump is required to read MSI Property table")
    with tempfile.TemporaryDirectory(prefix="huntress-msi-") as temporary:
        root = pathlib.Path(temporary)
        source = root / "assigned.msi"
        output = root / "tables"
        output.mkdir()
        source.write_bytes(data)
        try:
            completed = subprocess.run(
                [msidump, "-d", str(output), str(source)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SolverError(f"{label}: msidump timed out reading the MSI tables") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise SolverError(f"{label}: msidump could not read MSI tables: {detail}")
        property_table = output / "Property.idt"
        if not property_table.is_file():
            raise SolverError(f"{label}: MSI Property table was not emitted")
        lines = property_table.read_text(encoding="utf-8-sig").splitlines()
        if len(lines) < 4:
            raise SolverError(f"{label}: MSI Property table is incomplete")
        columns = lines[0].split("\t")
        if "Property" not in columns or "Value" not in columns:
            raise SolverError(f"{label}: MSI Property table has unexpected columns")
        property_index = columns.index("Property")
        value_index = columns.index("Value")
        matches = []
        for line in lines[3:]:
            cells = line.split("\t")
            if max(property_index, value_index) >= len(cells):
                continue
            if cells[property_index] == "ProductCode":
                matches.append(cells[value_index])
        if len(matches) != 1:
            raise SolverError(
                f"{label}: expected one MSI ProductCode property, found {len(matches)}"
            )
        value = matches[0]
        if value.startswith("{") and value.endswith("}"):
            value = value[1:-1]
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        ):
            raise SolverError(f"{label}: MSI ProductCode is not canonical GUID text")
        return value.lower()


def apk_package_name(data: bytes, label: str) -> str:
    """Read the package identity from an APK's compiled manifest with aapt."""
    aapt = shutil.which("aapt")
    if aapt is None:
        raise SolverError(f"{label}: aapt is required to read the compiled APK manifest")
    with tempfile.NamedTemporaryFile(prefix="huntress-apk-", suffix=".apk") as source:
        source.write(data)
        source.flush()
        try:
            completed = subprocess.run(
                [aapt, "dump", "badging", source.name],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SolverError(f"{label}: aapt timed out reading the APK manifest") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SolverError(f"{label}: aapt could not read the APK manifest: {detail}")
    matches = re.findall(
        r"(?m)^package:\s+name='([^']+)'(?:\s|$)",
        completed.stdout,
    )
    if len(matches) != 1:
        raise SolverError(
            f"{label}: expected one package name in aapt output, found {len(matches)}"
        )
    return matches[0]


def email_message_id(data: bytes, label: str) -> str:
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        raise SolverError(f"{label}: email message could not be parsed") from exc
    value = message.get("Message-ID")
    return str(value).strip() if value is not None else "none"


def wav_codec_name(data: bytes, label: str) -> str:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise SolverError(f"{label}: not a RIFF/WAVE file")
    offset = 12
    fmt = None
    while offset + 8 <= len(data):
        chunk_id = data[offset : offset + 4]
        size = struct.unpack_from("<I", data, offset + 4)[0]
        start, end = offset + 8, offset + 8 + size
        if end > len(data):
            raise SolverError(f"{label}: WAVE chunk extends beyond the file")
        if chunk_id == b"fmt ":
            fmt = data[start:end]
            break
        offset = end + (size & 1)
    if fmt is None or len(fmt) < 16:
        raise SolverError(f"{label}: WAVE format chunk is missing or truncated")
    format_tag, _channels, _rate, _byte_rate, _align, bits = struct.unpack_from(
        "<HHIIHH", fmt, 0
    )
    if format_tag == 0xFFFE:
        if len(fmt) < 40:
            raise SolverError(f"{label}: WAVE extensible format chunk is truncated")
        format_tag = struct.unpack_from("<H", fmt, 24)[0]
    if format_tag == 1:
        suffix = {8: "u8", 16: "s16le", 24: "s24le", 32: "s32le"}.get(bits)
        if suffix:
            return f"pcm_{suffix}"
    if format_tag == 3:
        suffix = {32: "f32le", 64: "f64le"}.get(bits)
        if suffix:
            return f"pcm_{suffix}"
    if format_tag == 6:
        return "pcm_alaw"
    if format_tag == 7:
        return "pcm_mulaw"
    raise SolverError(
        f"{label}: unsupported WAVE codec tag 0x{format_tag:04x} at {bits} bits"
    )


def primary_audio_codec_name(data: bytes, label: str) -> str:
    if data.startswith(b"fLaC"):
        return "FLAC"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return wav_codec_name(data, label)

    mediainfo = shutil.which("mediainfo")
    if mediainfo is None:
        raise SolverError(f"{label}: mediainfo is required to identify this audio stream")
    with tempfile.NamedTemporaryFile(prefix="huntress-audio-", suffix=".bin") as source:
        source.write(data)
        source.flush()
        try:
            completed = subprocess.run(
                [mediainfo, "--Output=JSON", source.name],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SolverError(f"{label}: mediainfo timed out reading audio metadata") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SolverError(f"{label}: mediainfo could not identify the audio stream: {detail}")
    try:
        tracks = json.loads(completed.stdout)["media"]["track"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SolverError(f"{label}: mediainfo returned malformed audio JSON") from exc
    audio_tracks = [
        track for track in tracks
        if track.get("@type") == "Audio" and isinstance(track.get("Format"), str)
    ]
    if not audio_tracks:
        raise SolverError(f"{label}: no audio codec format was reported")
    return audio_tracks[0]["Format"]


def mp4_primary_video_dimensions(data: bytes, label: str) -> str:
    mediainfo = shutil.which("mediainfo")
    if mediainfo is None:
        raise SolverError(f"{label}: mediainfo is required to read MP4 stream metadata")
    with tempfile.NamedTemporaryFile(prefix="huntress-media-", suffix=".mp4") as source:
        source.write(data)
        source.flush()
        try:
            completed = subprocess.run(
                [mediainfo, "--Output=JSON", source.name],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SolverError(f"{label}: mediainfo timed out reading stream metadata") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SolverError(f"{label}: mediainfo could not read the MP4: {detail}")
    try:
        tracks = json.loads(completed.stdout)["media"]["track"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SolverError(f"{label}: mediainfo returned malformed JSON") from exc
    videos = [
        track for track in tracks
        if track.get("@type") == "Video"
        and str(track.get("Width", "")).isdigit()
        and str(track.get("Height", "")).isdigit()
    ]
    if not videos:
        raise SolverError(f"{label}: MP4 has no video stream with pixel dimensions")
    return f"{videos[0]['Width']}x{videos[0]['Height']}"


def macho_cpu_type_set(data: bytes, label: str) -> str:
    thin_magics = {
        b"\xce\xfa\xed\xfe": "<",
        b"\xcf\xfa\xed\xfe": "<",
        b"\xfe\xed\xfa\xce": ">",
        b"\xfe\xed\xfa\xcf": ">",
    }
    cpu_names = {
        7: "i386",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
        0x0200000C: "arm64_32",
        18: "powerpc",
        0x01000012: "powerpc64",
    }
    values: list[str] = []
    if data[:4] in thin_magics:
        endian = thin_magics[data[:4]]
        if len(data) < 8:
            raise SolverError(f"{label}: truncated Mach-O header")
        cpu_type = struct.unpack_from(endian + "I", data, 4)[0]
        if cpu_type not in cpu_names:
            raise SolverError(f"{label}: unsupported Mach-O CPU type 0x{cpu_type:08x}")
        values.append(cpu_names[cpu_type])
    else:
        fat_magics = {
            b"\xca\xfe\xba\xbe": ">",
            b"\xbe\xba\xfe\xca": "<",
            b"\xca\xfe\xba\xbf": ">",
            b"\xbf\xba\xfe\xca": "<",
        }
        endian = fat_magics.get(data[:4])
        if endian is None or len(data) < 8:
            raise SolverError(f"{label}: unsupported Mach-O container header")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        entry_size = 32 if data[:4] in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca") else 20
        if count == 0 or 8 + count * entry_size > len(data):
            raise SolverError(f"{label}: invalid fat Mach-O architecture table")
        for index in range(count):
            cpu_type = struct.unpack_from(endian + "I", data, 8 + index * entry_size)[0]
            if cpu_type not in cpu_names:
                raise SolverError(f"{label}: unsupported Mach-O CPU type 0x{cpu_type:08x}")
            name = cpu_names[cpu_type]
            if name not in values:
                values.append(name)
    return json.dumps(values, separators=(",", ":"))


def synthesis_sha256_order(
    question: dict[str, Any], files: list[tuple[str, bytes]], answer_id: str
) -> str:
    prompt = str(question.get("question", ""))
    match = re.search(r"\bFiles:\s*(\[[^\r\n]*\])", prompt)
    if not match:
        raise SolverError(f"{answer_id}: question does not state the ordered-hash file list")
    try:
        filenames = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise SolverError(f"{answer_id}: question file list is not valid JSON") from exc
    if (
        not isinstance(filenames, list)
        or not filenames
        or not all(isinstance(name, str) for name in filenames)
        or len(set(filenames)) != len(filenames)
    ):
        raise SolverError(f"{answer_id}: question file list is malformed")
    digests = []
    for filename in filenames:
        _label, content = unique_by_hint(
            files, filename, description=f"file named in {answer_id}"
        )
        digests.append((hashlib.sha256(content).hexdigest(), filename))
    return json.dumps(
        [filename for _digest, filename in sorted(digests)],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def solve_detailed(
    start: dict[str, Any], artifact_paths: list[pathlib.Path]
) -> tuple[dict[str, str], dict[str, str], bool]:
    answer_ids, replay = answer_ids_and_replay(start)
    questions = questions_by_id(start, answer_ids)
    member_groups = read_archive_members(artifact_paths)
    all_files = [member for group in member_groups for member in group]

    member_hints = {
        hinted_member(question)
        for question in questions.values()
        if hinted_member(question)
    }
    answers: dict[str, str] = {}
    reasoning: dict[str, str] = {}
    for answer_id, question in questions.items():
        hint_selection_reason = ""
        raw_artifact_hint = artifact_hint(question).strip()
        archive_hint = (
            raw_artifact_hint.rsplit("->", 1)[0].strip()
            if "->" in raw_artifact_hint
            else raw_artifact_hint
        )
        archive_name = pathlib.PurePosixPath(
            archive_hint.replace("\\", "/")
        ).name
        delivery_match = re.search(
            r"\bdelivery\s+(\d+)\b",
            raw_artifact_hint,
            re.IGNORECASE,
        )
        if len(artifact_paths) > 1 and delivery_match:
            delivery_index = int(delivery_match.group(1)) - 1
            if delivery_index < 0 or delivery_index >= len(member_groups):
                raise SolverError(
                    f"{answer_id}: artifact hint names an unassigned delivery"
                )
            scoped_files = member_groups[delivery_index]
        else:
            scoped_files = all_files

        hint = hinted_member(question)
        if hint is None:
            raw_hint = artifact_hint(question).strip()
            delivery_member = re.match(
                r"(?is)^delivery\s+\d+\s*[:/]\s*(.+)$", raw_hint
            )
            if delivery_member:
                hint = pathlib.PurePosixPath(
                    delivery_member.group(1).strip().replace("\\", "/")
                ).name
        if hint is None:
            prompt = str(question.get("question", "")).lower()
            if "exact filename of the roster" in prompt:
                roster_hints = {
                    hinted_member(candidate)
                    for candidate in questions.values()
                    if re.search(
                        r"\broster[^` ]*\.csv\b",
                        str(candidate.get("question", "")),
                        re.IGNORECASE,
                    )
                    and hinted_member(candidate)
                }
                if not roster_hints:
                    roster_matches = [
                        path for path, _payload in scoped_files
                        if re.fullmatch(
                            r"roster(?:-[A-Za-z0-9_-]+)?\.csv",
                            pathlib.PurePosixPath(path).name,
                            re.IGNORECASE,
                        )
                    ]
                    if len(roster_matches) == 1:
                        hint = roster_matches[0]
                if len(roster_hints) != 1:
                    if hint is None:
                        raise SolverError(
                            f"Question {answer_id!r} does not identify one roster member"
                        )
                else:
                    hint = next(iter(roster_hints))
            elif "compute the full-file sha-256 digest" in prompt:
                synthesis_files = re.search(
                    r"\bFiles:\s*(\[[^\r\n]*\])",
                    str(question.get("question", "")),
                )
                if not synthesis_files:
                    raise SolverError(
                        f"Question {answer_id!r} does not state its synthesis file list"
                    )
                try:
                    filenames = json.loads(synthesis_files.group(1))
                except json.JSONDecodeError as exc:
                    raise SolverError(
                        f"Question {answer_id!r} has a malformed synthesis file list"
                    ) from exc
                if not isinstance(filenames, list) or not filenames:
                    raise SolverError(
                        f"Question {answer_id!r} has an empty synthesis file list"
                    )
                hint = str(filenames[0])
            elif "first evidence note" in prompt:
                matching_notes = [
                    (path, payload)
                    for path, payload in scoped_files
                    if "evidence-note" in pathlib.PurePosixPath(path).name.lower()
                    and (
                        not archive_name
                        or archive_name == pathlib.PurePosixPath(path).name
                        or f"/{archive_name}/" in path.replace("\\", "/")
                    )
                ]
                if not matching_notes:
                    matching_notes = [
                        (path, payload)
                        for path, payload in scoped_files
                        if "evidence-note"
                        in pathlib.PurePosixPath(path).name.lower()
                    ]
                if not matching_notes:
                    raise SolverError(f"Question {answer_id!r} asks for an evidence note, but none was found")
                hint = matching_notes[0][0]
                hint_selection_reason = (
                    "selected the first evidence note in ZIP central-directory order"
                )
            elif len(member_hints) == 1:
                hint = next(iter(member_hints))
            else:
                raise SolverError(
                    f"Question {answer_id!r} has no unique artifact member hint"
                )
        if archive_name and "->" in raw_artifact_hint:
            archive_member_hint = f"{archive_name}/{hint}"
            try:
                member_path, content = unique_by_hint(
                    scoped_files,
                    archive_member_hint,
                    description="evidence member",
                )
            except SolverError as exc:
                if "found 0)" not in str(exc):
                    raise
                member_path, content = unique_by_hint(
                    scoped_files, hint, description="evidence member"
                )
        elif archive_name and archive_name.lower().endswith(".zip") and "->" not in raw_artifact_hint:
            try:
                member_path, content = unique_by_hint(
                    scoped_files,
                    f"{archive_name}/{hint}",
                    description="evidence member",
                )
            except SolverError as exc:
                if "found 0)" not in str(exc):
                    raise
                member_path, content = unique_by_hint(
                    scoped_files, hint, description="evidence member"
                )
        else:
            member_path, content = unique_by_hint(
                scoped_files, hint, description="evidence member"
            )
        values = {
            "filename": pathlib.PurePosixPath(member_path).name,
            "size_bytes": str(len(content)),
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        question_text = str(question.get("question", "")).lower()
        if "jpeg.sof_dimensions_pixels" in question_text or "jpeg-sof-dimensions" in answer_id:
            width, height = jpeg_sof_dimensions(content)
            values["jpeg_sof_dimensions_pixels"] = f"{width}x{height}"
            field = "jpeg_sof_dimensions_pixels"
        elif "png.ihdr_dimensions_pixels" in question_text or "png-ihdr-dimensions" in answer_id:
            width, height, _ = png_ihdr_dimensions(content)
            values["png_ihdr_dimensions_pixels"] = f"{width}x{height}"
            field = "png_ihdr_dimensions_pixels"
        elif answer_id.endswith("pdf-header-version") or (
            "pdf.header_version" in question_text
        ):
            header = re.match(rb"%PDF-([0-9]+\.[0-9]+)", content)
            values["pdf_header_version"] = (
                header.group(1).decode("ascii") if header else "none"
            )
            field = "pdf_header_version"
        elif answer_id.endswith("zip-eocd-total-entries") or (
            "zip.eocd_total_entries" in question_text
        ):
            values["zip_eocd_total_entries"] = str(
                zip_eocd_total_entries(content, member_path)
            )
            field = "zip_eocd_total_entries"
        elif "central-directory-member-names" in answer_id:
            try:
                with zipfile.ZipFile(BytesIO(content)) as archive:
                    names = archive.namelist()
            except zipfile.BadZipFile as exc:
                raise SolverError(f"{member_path}: invalid nested ZIP") from exc
            values["zip_central_directory_member_names"] = json.dumps(
                names, separators=(",", ":"), ensure_ascii=False
            )
            field = "zip_central_directory_member_names"
        elif answer_id.endswith("synthesis-sha256-order"):
            values["metadata_day14_synthesis_sha256_order"] = synthesis_sha256_order(
                question, scoped_files, answer_id
            )
            field = "metadata_day14_synthesis_sha256_order"
        elif "pe-coff-machine-u16-hex" in answer_id:
            if len(content) < 0x40 or content[:2] != b"MZ":
                raise SolverError(f"{member_path}: PE DOS header is missing or truncated")
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            if (
                pe_offset + 6 > len(content)
                or content[pe_offset : pe_offset + 4] != b"PE\0\0"
            ):
                raise SolverError(f"{member_path}: PE signature or COFF header is missing")
            machine = struct.unpack_from("<H", content, pe_offset + 4)[0]
            values["pe_coff_machine_u16_hex"] = format_width_hex(machine, answer_id)
            field = "pe_coff_machine_u16_hex"
        elif "pe-address-of-entry-point-rva-hex" in answer_id:
            if len(content) < 0x40 or content[:2] != b"MZ":
                raise SolverError(f"{member_path}: PE DOS header is missing or truncated")
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            coff_offset = pe_offset + 4
            if (
                coff_offset + 20 > len(content)
                or content[pe_offset : pe_offset + 4] != b"PE\0\0"
            ):
                raise SolverError(f"{member_path}: PE signature or COFF header is missing")
            optional_size = struct.unpack_from("<H", content, coff_offset + 16)[0]
            optional_offset = coff_offset + 20
            if optional_size < 20 or optional_offset + optional_size > len(content):
                raise SolverError(
                    f"{member_path}: PE optional header is missing or truncated"
                )
            rva = struct.unpack_from("<I", content, optional_offset + 16)[0]
            values["pe_address_of_entry_point_rva_hex"] = format_width_hex(
                rva, answer_id
            )
            field = "pe_address_of_entry_point_rva_hex"
        elif "pe-version-original-filename" in answer_id:
            values["pe_version_original_filename"] = original_filename(
                content, member_path
            )[0]
            field = "pe_version_original_filename"
        elif "dotnet-mvid-guid" in answer_id:
            values["dotnet_mvid_guid"] = mvid_guid(content, member_path)
            field = "dotnet_mvid_guid"
        elif "msi-product-code-guid" in answer_id:
            values["msi_product_code_guid"] = msi_product_code(content, member_path)
            field = "msi_product_code_guid"
        elif (
            "apk-package-name" in answer_id
            or "apk.package_name" in question_text
        ):
            values["apk_package_name"] = apk_package_name(content, member_path)
            field = "apk_package_name"
        elif "ooxml-external-relationship-targets" in answer_id or (
            "ooxml.external_relationship_targets" in question_text
        ):
            values["ooxml_external_relationship_targets"] = json.dumps(
                _external_targets(content, member_path), separators=(",", ":")
            )
            field = "ooxml_external_relationship_targets"
        elif "email-message-id" in answer_id or "email.message_id" in question_text:
            values["email_message_id"] = email_message_id(content, member_path)
            field = "email_message_id"
        elif "primary-audio-codec-name" in answer_id or (
            "media.primary_audio_codec_name" in question_text
        ):
            values["primary_audio_codec_name"] = primary_audio_codec_name(
                content, member_path
            )
            field = "primary_audio_codec_name"
        elif "primary-video-dimensions" in answer_id or (
            "media.primary_video_dimensions" in question_text
        ):
            values["primary_video_dimensions"] = mp4_primary_video_dimensions(
                content, member_path
            )
            field = "primary_video_dimensions"
        elif answer_id.endswith("jar-main-class") or "jar.main_class" in question_text:
            values["jar_main_class"] = jar_manifest_main_class(content, member_path)
            field = "jar_main_class"
        elif "elf-e-machine-u16-hex" in answer_id or (
            "elf.e_machine_u16_hex" in question_text
        ):
            if len(content) < 20 or content[:4] != b"\x7fELF":
                raise SolverError(f"{member_path}: ELF header is missing or truncated")
            endian = {1: "<", 2: ">"}.get(content[5])
            if endian is None:
                raise SolverError(f"{member_path}: unsupported ELF byte order")
            machine = struct.unpack_from(endian + "H", content, 18)[0]
            values["elf_e_machine_u16_hex"] = format_width_hex(machine, answer_id)
            field = "elf_e_machine_u16_hex"
        elif "macho-cpu-type-set" in answer_id or (
            "macho.cpu_type_set" in question_text
        ):
            values["macho_cpu_type_set"] = macho_cpu_type_set(content, member_path)
            field = "macho_cpu_type_set"
        elif "lnk-target-path-windows" in answer_id:
            values["lnk_target_path_windows"] = lnk_target_path(content, member_path)
            field = "lnk_target_path_windows"
        elif (
            "evtx-record-count" in answer_id
            or "evtx.record_count" in question_text
        ):
            count, _evidence = evtx_record_count(content, member_path)
            values["evtx_record_count"] = str(count)
            field = "evtx_record_count"
        elif (
            "sqlite-page-size-bytes" in answer_id
            or "sqlite.page_size_bytes" in question_text
        ):
            values["sqlite_page_size_bytes"] = str(
                sqlite_page_size_bytes(content, member_path)
            )
            field = "sqlite_page_size_bytes"
        elif (
            "utf8-bom-present" in answer_id.lower()
            or "utf8_bom_present" in question_text
            or ("utf-8" in question_text and "bom" in question_text)
        ):
            values["utf8_bom_present"] = (
                "true" if content.startswith(b"\xef\xbb\xbf") else "false"
            )
            field = "utf8_bom_present"
        else:
            field = answer_id.rsplit("-", 1)[-1]
        aliases = {"size": "size_bytes", "bytes": "size_bytes"}
        field = aliases.get(field, field)
        if field not in values:
            if (
                "first" in question_text
                and "byte" in question_text
                or "prefix" in answer_id.lower()
            ):
                syntax = str(
                    question.get("answer_format", {}).get("syntax", "")
                ).lower()
                exact_hex_chars = re.search(
                    r"\bexact\s+(\d+)\s+hexadecimal characters?\b", syntax
                )
                if exact_hex_chars:
                    char_count = int(exact_hex_chars.group(1))
                    if char_count % 2:
                        raise SolverError(
                            f"{answer_id}: an odd hexadecimal character count "
                            "cannot encode a whole-byte prefix"
                        )
                    values["prefix_hex"] = content[: char_count // 2].hex()
                    field = "prefix_hex"
        if field not in values:
            prompt = str(question.get("question", "")).lower()
            if "filename" in prompt:
                field = "filename"
            elif "size" in prompt and "byte" in prompt:
                field = "size_bytes"
            elif "md5" in prompt:
                field = "md5"
            elif "sha-1" in prompt:
                field = "sha1"
            elif "sha-256" in prompt:
                field = "sha256"
        if field not in values:
            raise SolverError(f"Cannot determine requested metadata field {answer_id!r}")
        answers[answer_id] = values[field]
        validate_answer_format(answer_id, values[field], question)
        reasoning[answer_id] = (
            f"Read {len(content)} exact bytes from the assigned ZIP member "
            f"{hint!r}; derived {field} from those bytes."
            + (f" {hint_selection_reason}." if hint_selection_reason else "")
        )
    return answers, reasoning, replay


def solve(start: dict[str, Any], artifact_paths: list[pathlib.Path]) -> dict[str, str]:
    """Return answers keyed by the exact IDs in this start response."""
    answers, _, _ = solve_detailed(start, artifact_paths)
    return answers


def main() -> None:
    run_cli(solve_detailed, "Inventory and hash members from an assigned evidence ZIP")


if __name__ == "__main__":
    main()
