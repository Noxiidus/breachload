# Making breachload usable by beginners & learners

breachload today is powerful but assumes you already know pentesting: you write a
YAML, you read findings, you know what "kerberoast" or "SSTI" means. To make it a
tool a **layperson can run** and a **learner can grow with**, these are the gaps —
grouped, prioritised, and scoped so we can build them one at a time.

Legend: 🔴 high leverage · 🟡 medium · 🟢 polish · ✅ partially there

---

## 1. Onboarding — get started without knowing the tool

- 🔴 **`breachload init` wizard** — interactive Q&A that writes the engagement YAML
  for you: target(s), is-this-a-lab, listener IP (auto-detect tun0), mode. No YAML
  editing, no guessing field names.
- 🔴 **First-run authorization checklist** — before anything scans, a one-time
  prompt: "Do you have written permission for this scope? [y/N]", a link to what
  authorization means, and a note that unauthorized scanning is illegal.
- 🟡 **`breachload quickstart`** — one command that runs `doctor`, checks the VPN,
  seeds a sample engagement, and prints the exact next three commands to type.
- 🟡 **Lab-mode guardrail** — recognise practice ranges (HTB `10.10.10/11.x`,
  TryHackMe, `127.0.0.1`, RFC1918) and warn loudly when a target is *not* a known
  lab, so a beginner can't point it at the internet by accident.

## 2. Teaching — explain, don't just output

- 🔴 **Plain-language "why this matters"** on every finding and suggestion. ✅ partly
  (findings have descriptions) — extend to a consistent *what it is / why it's bad /
  what to do next* triplet, written for someone who's never seen it.
- 🔴 **`breachload explain <term>`** — an offline glossary: SSTI, kerberoast, LFI,
  ESC1, pass-the-hash, SUID… short definition + the command breachload would use +
  a "learn more" pointer (HackTricks / HTB Academy / GTFOBins / PayloadsAllTheThings).
- 🟡 **`--explain` / narrated mode** — the engine says *why* it chose each step in
  beginner language ("port 88 + LDAP means this is a Domain Controller, so…").
- 🟡 **MITRE ATT&CK tags** on findings — beginners see where each step sits in a
  recognised framework, and can study the technique id.
- 🟢 **Methodology checklists** per service/phase ("you found SMB — here are the 6
  things to always check"), so nothing obvious is missed.

## 3. Safety rails for people still learning

- 🔴 **`--dry-run`** everywhere — show exactly what *would* run (and why) without
  touching the target. The single most confidence-building feature for a beginner.
- 🟡 **Scope confirmation echo** — before the first active scan, print the resolved
  scope and make the user confirm it once.
- 🟢 **"Are you sure this is legal?" gating** on the aggressive modes (auto-exploit
  already gates hard; extend the spirit to first-time active scans).

## 4. Usability & environment

- 🔴 **`doctor --install`** — don't just report missing tools; print the exact
  `apt/pipx` install command for each, and (opt-in) run them. ✅ partly (doctor lists
  presence).
- 🟡 **Terminal UI (TUI)** — a live, keyboard-driven view of phases/hosts/findings
  for people who won't run the web dashboard. (`serve` covers the web case.)
- 🟡 **Clearer errors with fixes** — every failure ends with a "try this" line
  (✅ partly: config/state errors, MTU probe).
- 🟢 **Progress + phase status** — a always-visible "you are here" bar.

## 5. Reporting as a learning artifact

- 🔴 **Attack-path narrative** — the report tells the story: recon → foothold →
  privesc → root, in prose, with the *why* at each hop. Turns a solved box into a
  study document.
- 🟡 **Remediation explanations** written for understanding, not just "patch it".
- 🟢 **Cheat-sheet export** — the commands breachload suggested, grouped, as a
  copy-paste study sheet.

## 6. Knowledge depth (fewer dead ends)

- 🔴 **Grow the KBs** — web-app CVE KB, GTFOBins, payload library, chains. A beginner
  hits a wall the moment the tool has no entry for what they found; breadth is
  teaching. ✅ ongoing.
- 🟡 **Bundled sample engagements / walkthroughs** — a couple of fully-worked example
  states + reports shipped in-repo to read and learn from (see `WALKTHROUGH.md`).
- 🟢 **Auto CVE/KB refresh** — a maintained import pipeline so the KB stays current.

## 7. Practice-platform integration

- 🟡 **HTB / TryHackMe helpers** — VPN up-check, MTU fix (✅ `doctor --target`), box-IP
  setup, `/etc/hosts` write (✅ `hosts --write`). Package these into one "prep" step.
- 🟢 **Difficulty/verbosity profiles** — a "learner" profile that explains more and
  moves slower; a "pro" profile that's terse.

---

## Suggested build order (highest teaching-leverage first)

1. `init` wizard + first-run authorization checklist (§1) — removes the very first wall.
2. `explain <term>` glossary + consistent "why it matters" on findings (§2) — the core teaching loop.
3. `--dry-run` (§3) — safe experimentation.
4. `doctor --install` (§4) — get the environment working without frustration.
5. Attack-path narrative in the report (§5) — turns each run into a lesson.

Everything here respects the existing contract: deterministic core, safety layer
governs actions, and the beginner-facing features are about **explanation and
guardrails**, not lowering the safety bar.
