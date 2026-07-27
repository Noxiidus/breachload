# Security Policy

## Intended use

breachload is a tool for **authorized** security testing — penetration tests you
have written permission to perform, CTF/lab environments, and security research.
You are solely responsible for ensuring every target in an engagement's scope is
one you are authorized to test. Using it against systems without permission is
illegal and against the spirit of the project.

The safety layer (scope allowlist, confirmation gates on intrusive/exploit
actions) is a safeguard, not a substitute for authorization and judgment.

## Reporting a vulnerability

If you find a security issue **in breachload itself** (e.g. a scope-enforcement
bypass, a command-injection path in an adapter, secrets leaking into logs):

- **Do not** open a public issue.
- Email the maintainer or open a private [security advisory](https://github.com/Noxiidus/breachload/security/advisories/new).
- Include reproduction steps and the affected version.

Scope-enforcement and validator bypasses are treated as the highest priority,
since the whole autonomous model depends on them.

## Handling engagement data

- Engagement state, audit logs, loot, and artifacts are git-ignored by default.
- Never commit `engagements/<name>/`, `.env`, or any target/credential data.
- Treat `audit.jsonl` as sensitive: it records everything the agent did.
