# Huntress CTF 2026: Day 18

[← Day 17](../day-17/README.md) · [Overview](../README.md) · [Day 19 →](../day-19/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Off the Rails | Warmups | ✅ | ✅ | ✅ |

## Off the Rails

*Warmups*

A three-rail Rail Fence transposition. The characters follow rows 0, 1, 2, 1 repeatedly, so you count how many land on each row, split the ciphertext into those rows, and read back in zigzag order.

```python
rails, pattern, row, step = 3, [], 0, 1
for _ in text:
    pattern.append(row)
    step = 1 if row == 0 else -1 if row == rails - 1 else step
    row += step
rows, i = [], 0
for r in range(rails):
    n = pattern.count(r)
    rows.append(list(text[i:i + n]))
    i += n
print("".join(rows[r].pop(0) for r in pattern))
```

Stage `18` in Mastery (88 fields).
