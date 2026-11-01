# Build: Huntress CTF Solver Agent

You're going to build an agent that works through Huntress CTF 2026 challenges on its own, reusing and improving a library of solver scripts. Read this whole brief before writing any code. Then build it in the order given in **Build Order**, and stop at each checkpoint so I can review.

## Background

- We work in `/home/HuntressCTF`. Challenges are assigned and graded by the Game Master through the proxy used in `run_elf_challenge.py`.
- Each challenge has three modes: **Single Solve** (one artifact, no time limit), **Time Trial** (a fresh artifact with a deadline of about 30 seconds), and **Mastery** (several fresh artifacts with a tighter deadline). Every attempt gets new, randomized inputs.
- On Day 1, I solved challenges by having you write a reusable script, checking it on the Single Solve, then reusing it for the timed modes. These scripts already exist and work:
  - `metadata_hashes.py`: filename, size, and MD5/SHA-1/SHA-256 of a file inside a ZIP (You Must Be This Hash to Ride)
  - `analyze_powershell_samples.py`: static triage of PowerShell samples in an AES-encrypted ZIP (Power Play)
  - `run_elf_challenge.py`: ELF header, section, symbol, and disassembly analysis, plus Game Master start/retry/artifact/submit (ELF Aware)
  - A Little Based had no saved script: decode Base64 (strip any prefix), take the last non-empty line.
- Exported Trust (Android) is unsolved because it needs an emulator or device we don't have. That's the example of a challenge the agent should hand back to me instead of forcing.

The goal is to automate that loop: **find a challenge → understand it → reuse or build a solver → pass Single Solve → pass Time Trial and Mastery → record what was learned → move on.**

## Rules (these can't be broken)

These come from the Huntress CTF rules and from how I want to play. If any step would break one, stop and ask me.

1. **Only work on assigned artifacts.** Never attack the competition infrastructure, the Game Master, the proxy, or other players. Don't probe, fuzz, or guess at proxy endpoints. Only use operations you've seen work (listed under **Game Master API** below) or that the Game Master or challenge text describes.
2. **No automated scanners** (nmap, sqlmap, DirBuster, nikto, Metasploit, or similar) against challenge services.
3. **Never brute-force or guess answers.** Every answer you submit has to come from analyzing the artifact. Never loop through candidate values to see which one gets accepted. If you have two plausible answers for a field and can't tell which is right from the artifact, stop and ask me instead of trying both.
4. **Limit submissions.** At most **3 submissions per challenge mode**, and each resubmission needs a specific, written diagnosis of what was wrong and what changed. Once you hit the limit, hand the challenge back to me.
5. **Never share flags.** Flags are unique to our team. Store them only in the private flags file (see **Layout**), never in notes, logs meant for writeups, or console summaries. Refer to them as "flag received".
6. **Don't run artifacts.** Analyze statically (read, decode, parse, disassemble). If a challenge truly requires running an artifact, stop and ask me first.
7. **Don't spam for hints.** Work from the challenge text and the artifact. Don't repeatedly ask the Game Master or staff for help.
8. **Stay inside this environment.** No new accounts, credentials, payments, settings changes, device hosts, or network targets other than the Game Master proxy.

## Game Master API (seen in `run_elf_challenge.py`)

Confirm this against the existing code before relying on it, and don't try other endpoints.

- Start: `POST {"challenge": "<id>"}` returns `questions` (each with `id` and `artifact`), `answer_ids`, `attempt_id`, and `deadline`.
- Timed mode IDs are `<id>/time_trial` and `<id>/mastery`.
- Status: `GET ?op=status&challenge=<id>` returns the `deadline`.
- Retry an expired timed attempt: `POST {"op": "retry", "challenge": "<id>"}`.
- Artifact: `GET ?op=artifact&challenge=<id>[&delivery=<n>]` returns the ZIP bytes. Mastery can have several deliveries, numbered from 0.
- Submit: `POST {"challenge": "<id>", "answers": {<answer_id>: <value>}}` returns `result` (`CORRECT`/incorrect), `flag`, and `remaining`.
- Answer IDs can be plain (`message`), set-scoped (`set1.message`), or slot-scoped (`slot0_field`, `set1.slot0_field`). Always build answers from the exact `answer_ids` returned for *that* attempt.

How to list challenges and see which ones are complete isn't in the existing code. Find out from the Game Master or the challenge interface, using only documented or offered operations. If you can't find a supported way, ask me, and I'll give you the next challenge ID manually.

## Layout

```
/home/HuntressCTF/agent/
  gm_client.py         # the only code that talks to the Game Master
  ctf_agent.py         # the orchestrator (the loop below)
  registry.json        # what each solver handles
  solvers/             # one solver per challenge family
  artifacts/<challenge>/<attempt_id>/   # downloads, untrusted, one fresh folder each
  notes/<challenge>.md # what was learned, no flags (for my writeups)
  runs/<timestamp>.jsonl   # log of every action, no flags
  private/flags.json   # flags only; never printed or copied anywhere else
```

### `gm_client.py`

Move the Game Master code out of `run_elf_challenge.py` (start, status, retry, artifact, submit, deliveries, answer ID parsing) into one shared module. Solvers never make network calls themselves.

### The solver contract

Every solver in `solvers/` must:

- Take the Game Master start response and the paths of the downloaded artifacts as input.
- Return `{answer_id: value}` for exactly the `answer_ids` it was given, as JSON. Don't submit anything; the orchestrator does that.
- Support `--dry-run`, which prints answers and the reasoning for each field.
- Be deterministic and fast. A timed run (download + analyze + submit) should take under a third of the deadline.
- Never hard-code a value seen in a previous attempt. Filenames, member names, prefixes, counts, and symbol names all have to be read from the current artifact and questions.
- Return a clear error for a field it can't determine. Only use a fallback like `none` when the question's stated format allows it.

### `registry.json`

One entry per solver:

```json
{
  "name": "elf_analyzer",
  "path": "solvers/elf_analyzer.py",
  "challenge_ids": ["binary-reverse-engineering-day-01-c-elf-orientation"],
  "artifact_types": ["elf", "zip"],
  "question_fields": ["elf_class", "endianness", "machine", "elf_type", "marker", "has_symtab", "exported_symbol", "recover_code", "entry_point"],
  "modes_passed": ["single_solve", "time_trial", "mastery"],
  "known_variants": ["stripped (no symtab)", "section-beacon (recover_code=none)", "immediate-recovery (constant 7331)"],
  "notes": "notes/elf-aware.md"
}
```

## The Loop (`ctf_agent.py`)

Handle one challenge at a time, start to finish.

1. **Pick the next challenge.** Choose the next incomplete challenge, or take the ID I give you. Skip anything already marked handed back to me.
2. **Understand it.** Start Single Solve. Save the full challenge text, questions, answer IDs, and every answer format stated. Download the artifact into a new `artifacts/` folder. Identify each file by its magic bytes, not its name or extension, and look inside nested ZIPs.
3. **Choose a solver.** Compare the registry against this challenge's artifact types and question fields.
   - **Strong match** (same artifact type and most fields covered): dry-run it.
   - **Partial match:** extend the existing solver (new fields, new variants) rather than copying it. Re-test the old challenges it covers in dry-run mode afterward so the change doesn't break them.
   - **No match:** write a new solver that follows the contract, and add it to the registry.
4. **Pass Single Solve.** Dry-run, then check every answer against its stated format before submitting. Submit. If it's not CORRECT, compare each field to the question wording and the artifact, write down what was wrong, fix the solver, and resubmit (within the 3-submission limit).
5. **Prepare for variation before the timed modes.** List every assumption the solver makes (one file, one ZIP member, fixed names, a prefix that might be there or not, a symbol that might be missing, set/slot/delivery mapping). Then make it handle each one by reading the current inputs. Time the full loop.
6. **Time Trial, then Mastery.** Run each as a single command: start (or retry if expired) → download all deliveries → solve → submit. If it fails, save that attempt's artifact and answers, figure out the new variant, fix the solver, add the variant to `known_variants`, and retry (within the limit).
7. **Record.** Update the registry. Write `notes/<challenge>.md` (format below). Save the flags to `private/flags.json`. Add a line to the run log.
8. **Move on** to the next challenge.

## When to Hand a Challenge Back to Me

Stop working on the challenge, write a handoff, and **go on to the next challenge** (don't stop the whole run) if:

- It needs something we don't have: an emulator, device, GPU, special hardware, a new device host, or a settings change. Exported Trust is the example.
- It needs credentials, accounts, payments, or anything outside this environment.
- It requires running an artifact (rule 6).
- An answer is unclear and could only be settled by guessing (rule 3).
- A mode reached the 3-submission limit.
- More than **20 minutes** have gone into one challenge without passing Single Solve.
- Anything might break a rule, or you can't tell whether it would.

Write the handoff into `notes/<challenge>.md` under a `## Handed back` heading with: what's done, what's blocking it, exactly what I need to do, and how to resume afterward.

## Notes Format (`notes/<challenge>.md`)

These are for my writeups and for my own learning, so explain things as well as recording them:

- **Challenge:** name, ID, category, a one-line summary in your own words
- **Artifact:** what it was, and how you identified it
- **How it's solved:** the technique, explained so a beginner could follow it, plus the exact manual commands that solve it without the script
- **How the solver works:** the key logic, and which parts are specific to this challenge and which are general
- **Variants seen:** what the timed modes threw in and how the solver handles each one
- **Gotchas:** answer-format surprises, mistakes made, and what fixed them
- **Status per mode:** CORRECT / handed back (never flags)

## Run Modes

- `--supervised` (the default for the first runs): pause before **every** submission, show the answers and the reasoning for each field, and wait for me to approve.
- `--autonomous`: submit without pausing, with all the rules and handback conditions still in force.
- `--challenge <id>`: work on one specific challenge only.
- `--max-challenges N` / `--max-minutes M`: limits for a run. Default to 3 challenges or 60 minutes, whichever comes first.

At the end of each run, print a summary table: challenge, mode, result, number of submissions, time taken, solver used or built, and anything handed back. No flags.

## Build Order (stop at each checkpoint so I can review)

1. **Shared client and registry.** Build `gm_client.py` from the existing code, and write registry entries for the four Day 1 challenges. **Checkpoint:** show me the client and the registry.
2. **Convert the existing solvers.** Move `metadata_hashes.py`, `analyze_powershell_samples.py`, the ELF analysis, and the Base64 decode into `solvers/` following the contract. Check them in **dry-run only** against fresh Single Solve artifacts. Don't resubmit challenges that are already solved. **Checkpoint:** show me the dry-run output.
3. **Orchestrator.** Build `ctf_agent.py` with the loop, the handback rules, the submission limits, logging, and the run modes. **Checkpoint:** walk me through it.
4. **Supervised test.** Run `--supervised --challenge <one Day 2 challenge I choose>` and go through all three modes, with me approving each submission. **Checkpoint:** show me the notes file and the run summary.
5. **Reusable skill.** Turn the loop into a skill like the existing `huntress-powerplay-timed`, so a future session can start it with one prompt.
6. Only after I approve: `--autonomous` runs on the remaining challenges.

Don't skip checkpoints. If something in this brief turns out to be wrong about the environment (an API detail, a file path, a tool that isn't installed), tell me what you found instead of working around it quietly.
