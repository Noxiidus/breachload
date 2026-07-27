# Contributing to breachload

## Ground rules

breachload has one architectural rule that overrides convenience:

> **The deterministic core owns the truth. The LLM only decides and explains.**

Parsing, scope enforcement, and state mutation live in code and are tested.
The model never parses raw tool output and never bypasses the safety layer.
A PR that routes tool output through the LLM for parsing, or that lets the
planner reach a target without going through `Validator.check`, will not be
merged.

## Development setup

```bash
git clone https://github.com/Noxiidus/breachload
cd breachload
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Adding a tool adapter

Adapters are the main extension point. Each one:

1. Subclasses `ToolAdapter` (`tools/base.py`).
2. Declares `name`, `binary`, `risk` (see the `Risk` enum), and `capabilities`.
3. Implements `build_command()` returning an **argv list** — never a shell string.
4. Implements `parse()` to fold output into `EngagementState`. Prefer a
   machine-readable output format (XML/JSON) over scraping human text.
5. Is registered in `tools/registry.py` (this also authorizes its binary).

See `tools/nmap.py` as the reference. Pick the `risk` class honestly: anything
that can brute-force, dump, exploit, or damage a target must be `INTRUSIVE` or
higher so the safety layer gates it.

## Commits & versioning

- [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `chore:`.
- [Semantic Versioning](https://semver.org). Update `CHANGELOG.md` under
  `[Unreleased]` in the same PR.
- Do not sign commits with tool/assistant attribution.

## Before opening a PR

```bash
ruff check .
pytest
```

Safety-layer changes (`safety/`) require accompanying tests.
