# Huntress CTF 2026: Day 26

[← Day 25](../day-25/README.md) · [Overview](../README.md) · [Day 27 →](../day-27/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Food for Thought | Warmups | ✅ | not started | not started |
| Before You Go | Metadata Forensics | ✅ | not started | not started |

Two web challenges from this day (Trust the Webhook, Serialized Offender) were not attempted.

## Food for Thought

*Warmups*

The artifact is a Brainfuck-style program. The agent handed this back under its "don't run artifacts" rule, but I overruled that for this case: these languages can only move a pointer, change bytes, and print characters. They can't touch files or the network. So the agent wrote a small pure-Python interpreter with no input and a 10-million-step limit, treated as a decoder rather than as running code.

## Before You Go

*Metadata Forensics*

Windows 10 Prefetch files are compressed (the `MAM` format, using XPRESS Huffman). This needed one approved package, `dissect.util`, for the decompression. It's the same artifact I parsed with PECmd in [THM Windows Forensics 2](../../../thm/windows-forensics-2/README.md), except this time the decompression was visible.
