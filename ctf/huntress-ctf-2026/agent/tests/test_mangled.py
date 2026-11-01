from __future__ import annotations

import hashlib
import io
import pathlib
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

from agent.solvers.common import elf_machine_name, load_start
from agent.solvers.mangled import (
    analyze_pe,
    answer_pe_import,
    assigned_members,
    field_name,
    solve_detailed,
    specimen_type,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
SAVED_ATTEMPT = (
    ROOT
    / "agent/artifacts/binary-reverse-engineering-day-02-cpp-and-pe-orientation"
    / "41ef63d2-b7c9-45cf-b6de-49241d8771ac"
)
ACCEPTED_ANSWERS = {
    "c_sha256": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
    "c_marker": "BR01-CATALOG-000",
    "c_has_symtab": "true",
    "c_recover_code": "8100",
    "c_machine": "x86-64",
    "cpp_sha256": "e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7",
    "cpp_format": "ELF",
    "cpp_xor_key": "0x31",
    "cpp_config_crc32": "0x6149aa00",
    "campaign": "BR02-000",
    "domain": "node-000.day02.example.invalid",
    "url": "https://node-000.day02.example.invalid/api/BR02-000",
    "mutex": "Global\\HuntressBR02_000",
    "has_cpp_vtable": "true",
    "has_cpp_typeinfo": "true",
    "mangled_score_symbol": "_ZNK15DiscoveryEngine5scoreEPKc",
    "vtable_symbol": "_ZTV15DiscoveryEngine",
}


class MangledSolverTests(unittest.TestCase):
    def test_saved_single_solve_reproduces_all_accepted_fields(self) -> None:
        start = load_start(SAVED_ATTEMPT / "start.json")
        answers, _, replay = solve_detailed(
            start, [SAVED_ATTEMPT / "artifact-00.bin"]
        )

        self.assertFalse(replay)
        self.assertEqual(set(answers), set(start["answer_ids"]))
        self.assertEqual(answers, ACCEPTED_ANSWERS)
        self.assertEqual(len(answers), 17)

    def test_multiple_members_and_sets_follow_each_artifact_hint(self) -> None:
        start = load_start(SAVED_ATTEMPT / "start.json")
        original_members, _ = assigned_members(
            [SAVED_ATTEMPT / "artifact-00.bin"]
        )
        by_name = {path.rsplit("/", 1)[-1]: data for path, data in original_members}
        c_bytes = by_name["day01-c.elf"]
        cpp_bytes = by_name["day02-cpp.elf"]
        set_b_c = c_bytes + b"\x00"
        set_b_cpp = cpp_bytes + b"\x00"

        with tempfile.TemporaryDirectory() as directory:
            artifact_path = pathlib.Path(directory) / "synthetic-mastery.zip"
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("set-a/day01-c.elf", c_bytes)
                archive.writestr("set-a/day02-cpp.elf", cpp_bytes)
                archive.writestr("set-b/day01-c.elf", set_b_c)
                archive.writestr("set-b/day02-cpp.elf", set_b_cpp)
                archive.writestr("decoys/not-a-specimen.bin", b"decoy")
            artifact_path.write_bytes(buffer.getvalue())

            questions_by_id = {
                question["id"]: question for question in start["questions"]
            }
            synthetic_ids = []
            synthetic_questions = []
            expected: dict[str, str] = {}
            for set_name, prefix, c_member, cpp_member, expected_c, expected_cpp in (
                (
                    "set1",
                    "set-a",
                    "set-a/day01-c.elf",
                    "set-a/day02-cpp.elf",
                    c_bytes,
                    cpp_bytes,
                ),
                (
                    "set2",
                    "set-b",
                    "set-b/day01-c.elf",
                    "set-b/day02-cpp.elf",
                    set_b_c,
                    set_b_cpp,
                ),
            ):
                for answer_id in start["answer_ids"]:
                    field = field_name(answer_id)
                    synthetic_id = f"{set_name}.{field}"
                    source_question = questions_by_id[answer_id]
                    is_c = field.startswith("c_")
                    member = c_member if is_c else cpp_member
                    question = dict(source_question)
                    question["id"] = synthetic_id
                    question["artifact"] = f"synthetic-mastery.zip -> {member}"
                    synthetic_ids.append(synthetic_id)
                    synthetic_questions.append(question)

                    if is_c:
                        expected[synthetic_id] = (
                            hashlib.sha256(expected_c).hexdigest()
                            if field == "c_sha256"
                            else ACCEPTED_ANSWERS[field]
                        )
                    else:
                        expected[synthetic_id] = (
                            hashlib.sha256(expected_cpp).hexdigest()
                            if field == "cpp_sha256"
                            else ACCEPTED_ANSWERS[field]
                        )

            synthetic_start = {
                "answer_ids": synthetic_ids,
                "questions": synthetic_questions,
            }
            answers, reasoning, replay = solve_detailed(
                synthetic_start, [artifact_path]
            )

        self.assertFalse(replay)
        self.assertEqual(set(answers), set(synthetic_ids))
        self.assertEqual(answers, expected)
        self.assertEqual(answers["set1.vtable_symbol"], "_ZTV15DiscoveryEngine")
        self.assertEqual(answers["set2.c_machine"], "x86-64")
        self.assertNotEqual(answers["set1.c_sha256"], answers["set2.c_sha256"])
        self.assertNotEqual(answers["set1.cpp_sha256"], answers["set2.cpp_sha256"])
        self.assertIn("set-a/day02-cpp.elf", reasoning["set1.vtable_symbol"])
        self.assertIn("set-b/day02-cpp.elf", reasoning["set2.vtable_symbol"])

    def test_machine_mapping_is_shared_short_form(self) -> None:
        self.assertEqual(
            elf_machine_name("Advanced Micro Devices X86-64"),
            "x86-64",
        )
        self.assertEqual(elf_machine_name("AArch64"), "AArch64")

    def test_pe_mz_detection_and_objdump_import_extraction(self) -> None:
        config_bytes = b'{"campaign":"BR02-PE","domain":"example.invalid","url":"https://example.invalid","mutex":"Global\\\\Sample"}'
        key = 0x31
        encoded = bytes(byte ^ key for byte in config_bytes)
        section = (
            b"HCFG"
            + bytes((1, key))
            + len(encoded).to_bytes(2, "little")
            + bytes(4)
            + encoded
        )
        fake_outputs = {
            ("objdump", "-p"): """\
sample.exe:     file format pei-x86-64
The Import Tables (interpreted .idata section contents)
 DLL Name: KERNEL32.dll
 vma: Hint/Ord Member-Name Bound-To
 1036c 293 DeleteCriticalSection
 10384 331 ExitProcess
 DLL Name: USER32.dll
 vma: Hint/Ord Member-Name Bound-To
 10476 89 MessageBoxA
The Function Table (interpreted .pdata section contents)
""",
            ("objdump", "-t"): (
                "0000 .rdata$_ZTV15DiscoveryEngine\n"
                "0001 _ZTV15DiscoveryEngine\n"
                "0002 _ZTI15DiscoveryEngine\n"
                "0003 _ZNK15DiscoveryEngine5scoreEPKc\n"
            ),
            ("c++filt",): "DiscoveryEngine::score(char const*) const",
        }

        def fake_static_tool(*args: str) -> str:
            if args[:1] == ("objcopy",):
                section_path = pathlib.Path(args[2].split("=", 1)[1])
                section_path.write_bytes(section)
                return ""
            return fake_outputs[args[:2] if args[:1] == ("objdump",) else args[:1]]

        with (
            mock.patch("agent.solvers.mangled._objdump_supports_pe", return_value=True),
            mock.patch("agent.solvers.mangled.run_static_tool", side_effect=fake_static_tool) as run_tool,
        ):
            fields = analyze_pe(b"MZsynthetic-pe-bytes", "sample.exe")

        self.assertEqual(specimen_type(b"MZsynthetic-pe-bytes", "sample.exe"), "cpp")
        self.assertEqual(
            fields["imports"],
            [
                ("KERNEL32.dll", ["DeleteCriticalSection", "ExitProcess"]),
                ("USER32.dll", ["MessageBoxA"]),
            ],
        )
        self.assertEqual(fields["xor_key"], "0x31")
        self.assertEqual(
            fields["config_crc32"],
            f"0x{zlib.crc32(config_bytes) & 0xffffffff:08x}",
        )
        self.assertEqual(fields["vtable_symbol"], "_ZTV15DiscoveryEngine")
        self.assertEqual(
            answer_pe_import(
                "cpp_imported_dlls",
                {
                    "question": "Which DLLs are imported?",
                    "answer_format": {
                        "kind": "exact_text",
                        "syntax": "comma-separated DLL names",
                    },
                },
                fields,
            ),
            "KERNEL32.dll, USER32.dll",
        )
        self.assertIn(
            ("objdump", "-p"),
            [call.args[:2] for call in run_tool.call_args_list],
        )
        self.assertEqual(fields["sha256"], hashlib.sha256(b"MZsynthetic-pe-bytes").hexdigest())

    def test_pe_import_answer_fails_when_format_is_ambiguous(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "do not identify an unambiguous"):
            answer_pe_import(
                "cpp_imports",
                {
                    "question": "What is the import table?",
                    "answer_format": {"kind": "exact_text", "syntax": "exact text"},
                },
                {"imports": [("KERNEL32.dll", ["ExitProcess"])]},
            )


if __name__ == "__main__":
    unittest.main()
