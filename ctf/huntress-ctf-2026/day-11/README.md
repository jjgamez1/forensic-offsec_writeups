# Huntress CTF 2026: Day 11

[← Day 10](../day-10/README.md) · [Overview](../README.md) · [Day 12 →](../day-12/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Safe Travels | Warmups | ✅ | ✅ | ✅ |
| What's My Name Again? | Metadata Forensics | ✅ | ✅ | ✅ |
| D-Day | Binary Reverse Engineering | ✅ | ✅ | ✅ |

## Safe Travels

*Warmups*

"Our usual base went on a URL-friendly vacation", a Base64 variant added as stage `11`.

## What's My Name Again?

*Metadata Forensics*

Filenames were randomized, but the PE version resource keeps `OriginalFilename`. Parse the `RT_VERSION` resource to find what each binary calls itself.

## D-Day

*Binary Reverse Engineering*

D language templates: trace the runtime's expansions back to the config they built.
