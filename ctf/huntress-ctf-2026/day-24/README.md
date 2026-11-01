# Huntress CTF 2026: Day 24

[← Day 23](../day-23/README.md) · [Overview](../README.md) · [Day 25 →](../day-25/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| String Theory | Warmups | ✅ | ✅ | ✅ |
| Event Horizon | Metadata Forensics | ✅ | ❌ | not started |
| Spot the Difference | Binary Reverse Engineering | ❌ | not started | not started |

## String Theory

*Warmups*

Counted character runs (`count:character`, comma-separated), stage `24`. The trap is a literal comma used as data, as in `1:,,`. You have to consume exactly one character after the colon before looking for the separator, so a simple `split(",")` breaks.

## Event Horizon

*Metadata Forensics*

Count Windows EVTX records. Single Solve passed. One Time Trial failure exposed a real bug: the solver used the file size as the SQLite page size, when bytes 16–17 of the header hold it, and `00 01` there means 65,536. That fix wasn't enough, and the next submission failed too.

## Spot the Difference

*Binary Reverse Engineering*

Patch diffing between vulnerable and corrected builds, including JARs. 288 fields, incorrect.
