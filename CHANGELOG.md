# Changelog

All notable changes to breachload are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Reporting (`report/`): renders engagement state to a Markdown report —
  executive summary, host/service inventory, findings ordered by severity,
  credentials, generated artifacts, and an activity timeline. New
  `breachload report` command writes `engagements/<name>/report.md`.
- Exploit-side generation (`exploit/`): `Artifact` state model (generated
  payloads/PoCs as first-class records) and an `msfvenom` payload generator.
  Generation is offline and unrestricted — no target, no scope check — but still
  refuses shell-metacharacter injection. New `breachload payload` CLI command
  writes the artifact under `engagements/<name>/artifacts/` and records it in
  state. (Delivery against a target — the scope- and confirmation-gated step —
  is next.)
- Analysis layer (`analysis/`): version→CVE mapping from a local, offline
  knowledge base (`data/vuln_kb.json`) with a simple version-constraint matcher;
  a cross-service correlator (MS17-010/EternalBlue candidate, cleartext FTP/
  Telnet, anonymous FTP); and an `Analyzer` that folds both into findings,
  deduplicated. Wired into the orchestrator to enrich state after each step.
- Web-recon adapters: `whatweb` (HTTP fingerprinting → service product/techs),
  `ffuf` (content discovery → paths as notes + findings), `nuclei` (templated
  vuln scan → findings with mapped severity and CVE ids).
- `enum4linux-ng` adapter: SMB/NetBIOS enumeration → SMB service, null-session
  and readable-share findings, usernames as credential leads.
- OUTFILE mechanism in the adapter base: tools that emit machine-readable output
  to a file (not stdout) use the `{OUTFILE}` marker; the runner allocates a temp
  path, substitutes it, and reads the result back — safe under scope validation.
- Capability- and state-driven heuristic planner: selects the right tool per
  phase (recon→nmap, enum→whatweb/ffuf/enum4linux-ng, vuln→nuclei) and skips
  work already done.
- Automatic phase transitions: `Orchestrator.run_engagement` walks
  recon → enumeration → vuln; `breachload run` auto-chains by default, with
  `--phase` for a single phase and `--stop` to bound the chain.
- End-to-end orchestrator test proving the full chain populates state (38 tests).
- Exploit-side: msfvenom payload generator + Artifact state model — _planned_
- Web dashboard (FastAPI + WebSocket) for live follow-along and confirmation
  gates, on top of the orchestrator's `on_event` seam — _planned (v0.8)_

### Fixed
- Payload generation reports a clean error when the generator binary (e.g.
  msfvenom) is not installed, instead of crashing with a raw traceback.
- Engagement `mode` (advisor / semi-auto / full-auto) now actually controls the
  confirmation threshold instead of being a decorative field: advisor confirms
  every action, semi-auto auto-runs only passive/recon, full-auto uses
  `auto_threshold`.
- ffuf now attaches discovered paths to the correct service port (it previously
  assumed port 80, mislabelling services on 8080/8443/etc.).
- The orchestrator isolates tool failures: a crashing/timed-out/unparseable
  adapter no longer aborts the whole engagement — it is logged, recorded, and
  the run continues (and the record stops the planner re-proposing it).
- The Claude planner falls back to the heuristic on any API error (network, rate
  limit, auth) instead of crashing the run.
- `extract_targets` no longer misreads file-path arguments (e.g. a wordlist
  `common.txt`) as hostnames, which had blocked legitimate ffuf commands.
- nmap address parsing used a truthiness test on an XML element (deprecated and
  wrong for empty elements); now an explicit `is not None` check.
- CLI no longer crashes rendering help/output on non-UTF-8 Windows consoles
  (replaced `→`/box-drawing characters with ASCII).

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
