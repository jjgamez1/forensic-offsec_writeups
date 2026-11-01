# Huntress CTF 2026: Day 14

[← Day 13](../day-13/README.md) · [Overview](../README.md) · [Day 15 →](../day-15/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Seven Steps | Warmups | ✅ | ✅ | ✅ |
| The Shortcut Home | Metadata Forensics | ✅ | ❌ | not started |
| Selective Memory | Binary Reverse Engineering | ✅ | ✅ | ✅ |
| The API Has Opinions | Web Exploitation | not started | not started | not started |

## Seven Steps

*Warmups*

"Caesar took a week off": a Caesar shift of seven positions backward, added as stage `14`.

## The Shortcut Home

*Metadata Forensics*

Read a Windows `.lnk` file's target from its LinkInfo structure. Single Solve passed. The Time Trial was a 19-field mix of nearly every earlier file type, and all three submissions failed, including one where I fixed the padding of `pe.coff_machine_u16_hex`. I authorized that fix, and it wasn't the answer. I never found the wrong field.

## Selective Memory

*Binary Reverse Engineering*

Objective-C registers every class, selector, and string, so the persistence descriptor can be read directly. Includes a Base64-carried config and a literal one.

## The API Has Opinions

*Web Exploitation*

Not solved. No submission was made; the agent had no reviewed way to work this target.
