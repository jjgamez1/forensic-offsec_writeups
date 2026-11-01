# Huntress CTF 2026: Day 8

[← Day 7](../day-07/README.md) · [Overview](../README.md) · [Day 9 →](../day-09/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Entity Relations | Warmups | ✅ | ✅ | ✅ |
| What's in the Box? | Metadata Forensics | ✅ | ✅ | ✅ |
| Lost in Translation | Script Analysis | ❌ | not started | not started |
| Swift Justice | Binary Reverse Engineering | ✅ | ✅ | ✅ |

## Entity Relations

*Warmups*

Numeric HTML character references (`&#77;&#97;…`), decoded with Python's `html.unescape`. Added as stage `08`.

## What's in the Box?

*Metadata Forensics*

Inventory every stored path in the central directory, keeping order and directory context.

## Lost in Translation

*Script Analysis*

The same indicators across every language so far. Incorrect.

## Swift Justice

*Binary Reverse Engineering*

Swift symbols lead to the network configuration. Mastery's 400 fields hit the agent's 20-second analysis limit, because the solver was re-parsing every file for every question. Caching the results per file fixed it.
