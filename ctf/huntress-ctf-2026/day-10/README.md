# Huntress CTF 2026: Day 10

[← Day 9](../day-09/README.md) · [Overview](../README.md) · [Day 11 →](../day-11/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Thirty-Two Below | Warmups | ✅ | ✅ | ✅ |
| Where Do We Begin? | Metadata Forensics | ✅ | ✅ | ✅ |
| Bind Over Matter | Script Analysis | ❌ | not started | not started |
| Zig Zag | Binary Reverse Engineering | ✅ | ✅ | ✅ |
| Uploading Expectations | Web Exploitation | not started | not started | not started |

## Thirty-Two Below

*Warmups*

Base32, stage `10`. This one taught the strangest lesson of the warmups.

One Mastery blob out of 48 decoded to an answer with extra text after the slug: `handy-meadow-coral-13-10180`. The stated format said "submit the slug only", so the solver dropped the `-10180`, and the submission came back incorrect. Two theories came up (fragments sorted as text instead of numbers, or decimal/octal confusion in another blob), and checking disproved both: fragments were in file order, and all 48 blobs decoded to the exact expected sentence.

A fresh attempt with no suffix blob passed, which left the question open until it came up again on [Day 23](../day-23/README.md).

## Where Do We Begin?

*Metadata Forensics*

Read a PE's `AddressOfEntryPoint`. There was only one field, so when `0x65bd0` came back incorrect, that answer had to be the problem. The raw bytes (`d0 5b 06 00`) and `objdump -p` both confirmed the value, which left the spelling. `objdump` shows it as `00065bd0`, and the field is 4 bytes wide.

`0x00065bd0` was accepted. **Hex answers get zero-padded to the field's natural width.** Single-field challenges are valuable for exactly this reason: there's only one thing that can be wrong.

## Bind Over Matter

*Script Analysis*

Reconstruct WMI persistence from MOF files. 753 fields, incorrect. I stopped spending credits on this category after this, since each new day inherited the same unresolved failure.

## Zig Zag

*Binary Reverse Engineering*

Compare ELF and PE builds of the same Zig program.

## Uploading Expectations

*Web Exploitation*

Not solved. No submission was made; the agent had no reviewed way to work this target.
