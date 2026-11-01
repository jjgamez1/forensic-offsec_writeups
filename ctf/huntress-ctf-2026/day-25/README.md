# Huntress CTF 2026: Day 25

[← Day 24](../day-24/README.md) · [Overview](../README.md) · [Day 26 →](../day-26/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| You Have a Point | Warmups | ✅ | ✅ | ✅ |

Three web challenges from this day (Shell Company, Reset Expectations, Resolver Revolt) were not attempted.

## You Have a Point

*Warmups*

Explicit Unicode code points (`U+0041 U+0042 …`), stage `25`.

```python
"".join(chr(int(t[2:], 16)) for t in text.split())
```
