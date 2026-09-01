# Bug-Hunt Workflow

breachload takes correctness seriously — 800+ tests, mypy clean, ruff
clean, and multi-layer harnesses for the bugs unit tests miss. This page
is the maintenance discipline.

## The three harnesses

### 1. Unit tests (fast, run every commit)

```bash
pytest -q
```

Every module has direct tests. `test_registered_commands_pass_validator`
sweeps ALL registered adapters and asserts each default command passes the
safety validator — new adapters join automatically.

### 2. Fuzz harness (broad, catches regressions in parsers)

`tests/test_fuzz_parsers.py` uses `hypothesis` to feed ~200 adversarial
strings per parser (Kerberos, WinRM enum, ADCS certipy, BloodHound JSON,
DNS, appfinger, CVE version-spec, autofire, adchain, snmp/nfs/ftp/netexec).

Invariant: **arbitrary input must never crash a parser.** A real tool's
output is only ever weirder than any hand-written test.

Run with the rest:

```bash
pytest tests/test_fuzz_parsers.py -v
```

### 3. `doctor --self-test` (offline invariant check)

```bash
breachload doctor --self-test
```

Runs every adapter's default `build_command` through the Validator. Catches
a broken adapter or an over-eager registry addition without touching the
network. CI runs this on every push.

## The pre-push gate (mandatory)

Before every `git push`:

```bash
ruff check breachload/ tests/          # 0 errors
python -m mypy breachload/             # 0 errors
python -m pytest -q --no-cov           # all green
```

All three must be green. If any is red, fix it before pushing. Do not
"just see if CI passes" — that pattern created a run of CI-fail emails in
one earlier round.

## Adding a bug hunt

When adding a batch of features, follow up with a review pass:

1. Load the diff mentally — where would a real bug hide?
2. Sniff-test each new module: empty input, `None` input, absurd input,
   inputs that reach subprocess argv (POSIX rejects embedded NUL).
3. Cross-module contracts — new modules should slot into existing patterns
   (`Finding.confirm()`, `ToolResult`, `EngagementState`).
4. Fix + regression test each bug found. Write a short
   `docs/BUGHUNT-YYYY-MM-DD.md` naming the bugs + why the tests missed them.
5. Update `TECHNIQUE-COVERAGE.md` if the class layout changed.

## What we've found so far

- `docs/BUGHUNT-2026-08-23.md` — 2 ADCS + webcve parser bugs
- `docs/BUGHUNT-2026-08-30.md` — 1 bloodhound crash
- `docs/BUGHUNT-2026-08-30b.md` — 1 Kerberoast machine-account regex
- `docs/BUGHUNT-2026-08-30c.md` — 4 (MCP nmap wire, browser canary,
  `_is_external(None)`, MCP dead branch)
- `docs/BUGHUNT-2026-09-01.md` — 1 upload ladder NUL-byte

Pattern: bugs live in **new modules under adversarial input**, and in
**cross-module wiring** (module A hands B the wrong field). Both are what
the fuzz harness + self-test catch.

## Held-out coverage (dogfood measurement)

`tests/held_out/` — opt-in with `pytest -m held_out`. Loads per-box
`state.json` snapshots from real dogfood runs and asserts the expected
technique-class tokens show up in the state. See [Live Dogfood](Live-Dogfood).

## Rule of thumb

Every fix ships with a **regression test**. If a bug existed and no test
would have caught it, adding the test IS part of the fix.
