# Changelog

All notable changes to breachload are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Web-recon adapters (whatweb, ffuf, nuclei) — _planned_
- Exploit-side: msfvenom payload generator + Artifact state model — _planned_
- Web dashboard (FastAPI + WebSocket) for live follow-along and confirmation
  gates, on top of the orchestrator's `on_event` seam — _planned (v0.8)_

## [0.1.0] - 2026-07-27

Initial scaffold. Deterministic core with a working recon pipeline.

### Added
- Structured engagement state (`core/state.py`): Host, Service, Credential,
  Finding, ActionRecord models with JSON persistence.
- Safety layer (`safety/`): scope allowlist (CIDR/domain/exclude), command
  validator (binary allowlist, shell-metacharacter block, Risk classifier),
  append-only audit log.
- Tool adapter contract (`tools/base.py`) and the reference nmap adapter
  (XML → structured state).
- Orchestrator reasoning loop: plan → validate → run → parse → audit.
- Claude planner (`core/llm.py`) with an offline heuristic fallback so the
  pipeline runs without an API key.
- Engagement config (YAML) with per-engagement scope and autonomy threshold.
- Typer + Rich CLI: `breachload run`, `breachload status`.

[Unreleased]: https://github.com/Noxiidus/breachload/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Noxiidus/breachload/releases/tag/v0.1.0
