# Huntress CTF 2026: Day 4

[← Day 3](../day-03/README.md) · [Overview](../README.md) · [Day 5 →](../day-05/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Two of a Kind | Warmups | ✅ | ✅ | ✅ |
| Picture This | Metadata Forensics | ✅ | ✅ | ✅ |
| Dim and Dimmer | Script Analysis | ❌ | not started | not started |
| Go Fish | Binary Reverse Engineering | ✅ | ✅ | ✅ |

## Two of a Kind

*Warmups*

Whitespace-separated 8-bit binary, converted one token at a time to a byte and then decoded as UTF-8. Mastery added stage `04` (binary) to the Base64, ROT13, and hex pipeline, and each question's delivery and member hints both had to be honored.

## Picture This

*Metadata Forensics*

Read a JPEG's real dimensions from its structure: confirm the `FF D8` start, walk the marker segments using their big-endian lengths, and read height and width from the Start Of Frame marker. Answer format: `WIDTHxHEIGHT`.

## Dim and Dimmer

*Script Analysis*

Adds VBScript, for 231 fields in total. Reviewing it by hand produced three theories, and all three were wrong:

1. **Relay role:** the three `relay` specimens were answered `staged_chain`. But their decoded graphs end in `handoff_script`, which the rubric says *is* `staged_chain`.
2. **Batch control flow:** `for_indirect` paired with `direct` looked inconsistent. The raw lines showed the FOR loop is part of the statement itself, not a wrapper.
3. **`next_stage` values:** the Batch values looked unlike the other languages, but the decoded descriptor literally contains them.

Checking each theory before submitting meant none of them cost a submission.

## Go Fish

*Binary Reverse Engineering*

Go binaries ship build info, function names, and file paths. Read them statically.
