# Huntress CTF 2026: Day 2

[← Day 1](../day-01/README.md) · [Overview](../README.md) · [Day 3 →](../day-03/README.md)

| Challenge | Category | Single Solve | Time Trial | Mastery |
|---|---|---|---|---|
| Half a Turn | Warmups | ✅ | ✅ | ✅ |
| Looks Can Be Deceiving | Metadata Forensics | ✅ | ✅ | ✅ |
| Host With the Most | Script Analysis | ✅ | ✅ | ✅ |
| Mangled | Binary Reverse Engineering | ✅ | ✅ | ❌ |

## Half a Turn

*Warmups*

The clue was "thirteen steps forward", which means ROT13. Applying it twice gives back the original text, so decoding and encoding are the same operation. Decode the file, take the last non-empty line, and submit the slug after the final colon.

```bash
tr 'A-Za-z' 'N-ZA-Mn-za-m' < artifact.txt | tail -n 1
```

This challenge broke the first version of the solver in Mastery. Its ZIP held eight files, and the solver searched all of them for anything shaped like a slug, so it found eight candidates per question. The fix became a rule for every later solver: **use each question's artifact hint to pick exactly one file.**

This was also the first test of the agent, and it exposed a flaw in my process. I was approving each timed answer by hand and kept missing the deadline. So approval moved to before the clock starts (see the [overview](../README.md#how-the-agent-works)).

## Looks Can Be Deceiving

*Metadata Forensics*

Identify files by their first bytes, not their extensions. The answer was the first 16 bytes of each hinted member as lowercase hex. One Mastery variant included a PDF named `disguised-report.bin`.

```python
ZipFile(path).read(member)[:16].hex()
```

## Host With the Most

*Script Analysis*

Static analysis of PowerShell and JScript samples, with nothing ever executed. For each JScript file, read the `recover_*` routine and reverse its transforms in order: packed text, reversal, byte offset, and XOR. That yields a JSON descriptor containing an ordered `steps` graph, which the question's rubric maps to a role and a MITRE ATT&CK technique.

This was the only script challenge that passed. It's also the last one without Batch questions.

## Mangled

*Binary Reverse Engineering*

C++ symbol demangling and an XOR-encoded config section (`.hcfg`). This is the challenge where the review method proved itself. Three automated submissions failed, so I had the agent produce a table of all 17 fields and which ones had changed between submissions. Only two had:

| Submission | `vtable_symbol` | `c_machine` |
|---|---|---|
| 1 | mangled | long form |
| 2 | demangled | long form |
| 3 | demangled | `x86-64` |
| 4 ✅ | mangled | `x86-64` |

Each attempt fixed one field while the other was still wrong, so the right combination never got tried. The answer was the literal symbol table name, `_ZTV15DiscoveryEngine`, not the `c++filt` output.

Mastery failed on a set containing a real PE, and that one stayed unsolved. A wrong-file theory was disproved by a hash check.
