# Huntress CTF 2026: Day 5

[← Day 4](../day-04/README.md) · [Overview](../README.md) · [Day 6 →](../day-06/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| By the Numbers | Warmups | ✅ | ✅ | ✅ |
| Chunk Norris | Metadata Forensics | ✅ | ✅ | ✅ |
| Hatch Careful | Script Analysis | ❌ | not started | not started |
| Rust Belt | Binary Reverse Engineering | ✅ | ✅ | ✅ |

## By the Numbers

*Warmups*

Decimal byte values, plus stage `05` in Mastery (23 blobs).

```python
bytes(int(v) for v in text.split()).decode("utf-8")
```

## Chunk Norris

*Metadata Forensics*

The PNG equivalent: check the signature, walk the chunks using their 32-bit lengths, and verify each CRC. `IHDR` always comes first, and its first two big-endian integers are width and height.

## Hatch Careful

*Script Analysis*

Adds 14 Python carrier fixtures, parsed with `ast.parse` and never imported. 357 fields, incorrect on the first submission.

## Rust Belt

*Binary Reverse Engineering*

Rust binaries in both ELF and PE form. Mastery's second delivery used PE specimens the solver couldn't read yet, so it stopped before submitting. It then gained a PE section-table parser.
