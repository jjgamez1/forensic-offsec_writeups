# Huntress CTF 2026: Day 3

[← Day 2](../day-02/README.md) · [Overview](../README.md) · [Day 4 →](../day-04/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Hex Appeal | Warmups | ✅ | ✅ | ✅ |
| BOM Voyage | Metadata Forensics | ✅ | ✅ | ✅ |
| Expansion Pack | Script Analysis | ❌ | not started | not started |
| Table Manners | Binary Reverse Engineering | ✅ | ✅ | ✅ |

## Hex Appeal

*Warmups*

Single Solve and Time Trial were plain hex text: `bytes.fromhex(text).decode()`, then the last line. Mastery introduced the format used for the rest of the event: each blob holds **numbered stages**, each in a different encoding, and the decoded pieces join into one sentence. On Day 3 those were `01` Base64, `02` ROT13, and `03` hex.

The first Mastery bundle failed on those mixed stages before anything was submitted. The solver was extended and reviewed, and one retry passed.

## BOM Voyage

*Metadata Forensics*

Does each text file start with a UTF-8 byte order mark, `EF BB BF`? You test the extracted member's bytes, because editors hide the BOM. Mastery nested ZIPs inside a ZIP.

## Expansion Pack

*Script Analysis*

Adds Batch files. Besides the decoded descriptor, you classify how each script rebuilds it: `percent`, `delayed`, `call_double`, or `for_indirect` expansion, plus the control-flow wrapper around it. Two submissions failed, the second after a reviewed fix.

## Table Manners

*Binary Reverse Engineering*

.NET metadata and an embedded config. The agent stopped on a question it called underspecified, but the wording was exact: every nonempty `SHT_SYMTAB` name, in entry order, keeping duplicates. The catch is to read names from the raw `.strtab` bytes, because `readelf` may display section names for symbols whose own name is empty.
