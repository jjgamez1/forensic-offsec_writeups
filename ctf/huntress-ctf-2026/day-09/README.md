# Huntress CTF 2026: Day 9

[← Day 8](../day-08/README.md) · [Overview](../README.md) · [Day 10 →](../day-10/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Escape Room | Warmups | ✅ | ✅ | ✅ |
| Built Different | Metadata Forensics | ❌ | not started | not started |
| All the World's a Stager | Script Analysis | ❌ | not started | not started |
| Nimble | Binary Reverse Engineering | ✅ | ✅ | ✅ |
| Forged With Care | Web Exploitation | ✅ | ✅ | ✅ |

## Escape Room

*Warmups*

"These characters would very much like to escape" means JSON string escapes (`\u0079\u002d…`), added as stage `09`.

## Built Different

*Metadata Forensics*

Executables for several architectures, plus decoys with executable extensions. The Single Solve came back incorrect with no field-level feedback, and it stayed unsolved. The suspect at the time was the padding of a hex PE field, but that was never confirmed.

## All the World's a Stager

*Script Analysis*

Build a relationship graph between stagers. 695 fields, incorrect.

## Nimble

*Binary Reverse Engineering*

Nim compiles to C, but the generated names give it away.

## Forged With Care

*Web Exploitation*

Three small web targets. The agent's collector stayed strictly on the URLs each attempt assigned: one proof was in a backup listed as disallowed in `robots.txt`, one sat behind an access-control gap in an activity feed, and one needed a cross-site request (CSRF).
