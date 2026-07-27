# Safety Model

The safety layer is the spine of autonomous operation. It governs **where**
actions land and **when** a human is asked — not what the agent is allowed to
think about.

## What it does NOT restrict

Payload crafting, exploit development, shellcode generation, and PoC authoring
are core features and are **unrestricted**. These produce artifacts; they run
against nothing. The safety layer never inspects a command for being
"offensive."

## What it DOES gate

Every target-facing action passes `Validator.check()`, which enforces four
deterministic rules:

1. **Binary allowlist** — only registered tool binaries may run.
2. **No shell metacharacters** — commands are argv lists; `;`, `|`, `` ` ``,
   `$()`, redirects are rejected (this protects *you*, not the target).
3. **Scope** — every IP/host/URL in the args must be in the engagement's
   allowlist and not excluded. Off-scope → hard block.
4. **Risk threshold** — actions above `auto_threshold` require confirmation.

## Risk classes

| Class | Examples |
|---|---|
| `PASSIVE` | whois, DNS, cert transparency |
| `RECON` | nmap discovery, whatweb |
| `ACTIVE` | dir brute-force, nuclei, service enum |
| `INTRUSIVE` | auth brute-force, sqlmap dumping |
| `EXPLOIT` | exploit execution, shells, writes |
| `DESTRUCTIVE` | anything that can damage or DoS a target |

## Autonomy tuning

`auto_threshold` sets what runs without asking in full-auto mode:

- **CTF / lab:** raise it (e.g. `active` or higher) — clean scope, bounded blast
  radius, fast iteration.
- **Real engagement:** keep it low (`recon`) so exploitation and intrusive steps
  always stop for confirmation.

Same engine, different threshold. The generator side (payloads/PoCs) stays open
either way; only **delivery** is gated.

## Audit

Every plan, validation decision, block, and execution is appended to
`engagements/<name>/audit.jsonl`. It is the compliance trail and the raw material
for the report. Treat it as sensitive.
