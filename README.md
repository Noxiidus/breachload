# breachload

Autonomous pentest copilot for Linux. Guides an engagement from recon to report:
runs tools, parses their output into structured state, decides the next step, and
generates working notes and findings — while a deterministic safety layer keeps
every action inside the authorized scope.

> For authorized security testing, CTF/HTB, and research only. You are responsible
> for having permission to test every target in scope.

## Design

- **Deterministic core, LLM for decisions.** Parsing, state, and scope are code.
  The model (Claude) only decides the next action and explains why. It never
  parses raw output and never bypasses the safety layer.
- **Structured state, not chat history.** Every host / service / credential /
  finding is a typed record (`core/state.py`), queryable and reproducible.
- **Safety layer is the spine of full-auto** (`safety/`): scope allowlist,
  command validation (binary allowlist + no shell metacharacters), and a risk
  classifier that forces confirmation on intrusive/exploit/destructive actions.
- **Runs offline.** With no `ANTHROPIC_API_KEY`, a heuristic planner still drives
  recon end-to-end so the pipeline is testable without the API.

## Layout

```
breachload/
  core/        orchestrator, state, config, llm planner, phases
  safety/      scope, validator, audit
  tools/       adapters (run + parse -> struct); nmap is the reference
  analysis/    cve mapping, cross-service correlation   (planned)
  report/      findings -> markdown/pdf                  (planned)
engagements/   per-engagement scope + state + audit log
```

## Usage

```bash
pip install -e .
export ANTHROPIC_API_KEY=...        # optional; omit for offline heuristic mode
breachload run engagements/example.yaml --phase recon
breachload status engagements/example.yaml
```

## Autonomy & the safety layer

`auto_threshold` in the engagement YAML sets what runs without asking in
full-auto mode. Recon/enumeration flow automatically; anything the validator
classes above the threshold (brute-force, sqlmap dumping, exploit execution)
stops for confirmation. The safety layer governs **where** actions land and
**when** they need a human — it does not restrict analysis, payload crafting, or
exploit development.

## Roadmap

1. ~~Scaffold: state + safety + nmap adapter + advisor loop~~
2. Adapters: whatweb, ffuf, nuclei, enum4linux-ng
3. Analysis: version→CVE mapping, cross-service correlator
4. Full-auto with confirm-gates; kill-switch
5. Reporting engine
6. CTF mode (aggressive defaults, flag detection, light reporting)
```
