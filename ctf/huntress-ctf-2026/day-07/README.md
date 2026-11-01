# Huntress CTF 2026: Day 7

[← Day 6](../day-06/README.md) · [Overview](../README.md) · [Day 8 →](../day-08/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Percent Chance | Warmups | ✅ | ✅ | ✅ |
| Seven-Zip, No Relation | Metadata Forensics | ✅ | ✅ | ✅ |
| Node by Node | Script Analysis | ❌ | not started | not started |
| Routine Check | Binary Reverse Engineering | ✅ | ✅ | ✅ |

## Percent Chance

*Warmups*

"My address bar is having a moment" means URL percent-encoding (`%HH`), stage `07`. The first Mastery attempt stopped before submitting because that stage wasn't supported yet. After the fix and review, all 33 fields passed.

## Seven-Zip, No Relation

*Metadata Forensics*

Count what ZIP archives claim using the End Of Central Directory record. The solver's first version recursed into a nested ZIP but forgot to keep the nested ZIP's own bytes, so it couldn't read that archive's own entry count.

## Node by Node

*Script Analysis*

Adds Node.js operation graphs. Incorrect.

## Routine Check

*Binary Reverse Engineering*

Kotlin coroutines compile to state machines, recoverable from metadata.
