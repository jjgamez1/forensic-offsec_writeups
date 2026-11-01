# Huntress CTF 2026: Day 22

[← Day 21](../day-21/README.md) · [Overview](../README.md) · [Day 23 →](../day-23/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Deflated Ego | Warmups | ✅ | ✅ | ✅ |
| Main Character Energy | Metadata Forensics | ✅ | ❌ | not started |
| Bridge Troll | Binary Reverse Engineering | ❌ | not started | not started |

## Deflated Ego

*Warmups*

Base64 around a zlib stream, stage `22`. The solver uses a size-bounded decompressor so a malicious stream can't expand without limit.

```bash
base64 -d artifact.txt | python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))'
```

## Main Character Energy

*Metadata Forensics*

Read `Main-Class` from a JAR's `META-INF/MANIFEST.MF`, unfolding continuation lines. Single Solve passed; the Time Trial failed.

```bash
unzip -p application.jar META-INF/MANIFEST.MF
```

## Bridge Troll

*Binary Reverse Engineering*

A .NET assembly with a native bridge. 264 fields, incorrect.
