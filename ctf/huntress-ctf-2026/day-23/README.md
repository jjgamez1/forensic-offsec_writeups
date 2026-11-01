# Huntress CTF 2026: Day 23

[← Day 22](../day-22/README.md) · [Overview](../README.md) · [Day 24 →](../day-24/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Eighty-Five Alive | Warmups | ✅ | ✅ | ✅ |

## Eighty-Five Alive

*Warmups*

Adobe ASCII85, stage `23`. The question from [Day 10](../day-10/README.md) came back here. Blob 34 decoded to a slug followed by `-6761`, and slug-only came back incorrect again. Comparing the two challenges gave a pattern:

| Attempt | Blob with extra text? | Submitted | Result |
|---|---|---|---|
| Thirty-Two Below, first Mastery | yes | slug only | incorrect |
| Thirty-Two Below, retry | no | slug | correct |
| Eighty-Five Alive, first Mastery | yes | slug only | incorrect |
| Eighty-Five Alive, retry with the new rule | not recorded | full instructed value if present | correct |

The stated format is generic, while the decoded line says to submit "this exact answer". So the working rule became: **follow the instruction inside the artifact over the generic format text.** It's a strong pattern, not proof, since my notes don't show whether that last retry actually contained a suffix blob.
