# Huntress CTF 2026: Day 15

[← Day 14](../day-14/README.md) · [Overview](../README.md) · [Day 16 →](../day-16/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Room Forty-Seven | Warmups | ✅ | ✅ | ✅ |
| A Word to the Wise | Metadata Forensics | ❌ | not started | not started |
| Stripped | Binary Reverse Engineering | ✅ | ✅ | ✅ |
| Fetch Quest | Web Exploitation | not started | not started | not started |

## Room Forty-Seven

*Warmups*

ROT47, which rotates all printable ASCII, so "even the punctuation went for a spin". Added as stage `15`. Unlike ROT13, it changes digits and symbols too.

The first Mastery run stopped at stage 15 without submitting, then passed all 73 fields after the fix.

## A Word to the Wise

*Metadata Forensics*

A `.docx` is a ZIP. External links live in `word/_rels/document.xml.rels` as relationships with `TargetMode="External"`. The solver found both external targets in file order, and the submission came back incorrect. It's a one-field answer, so something about that list is wrong, but neither the agent nor I could prove what. I left it unsolved rather than trying other orderings at random.

## Stripped

*Binary Reverse Engineering*

No symbols, so the solver compares stripped and symbolized ELFs and reads a CRC-validated config from the stripped one.

## Fetch Quest

*Web Exploitation*

Not solved. No submission was made; the agent had no reviewed way to work this target.
