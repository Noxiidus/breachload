# Roadmap

breachload follows [Semantic Versioning](https://semver.org). Milestones map to
minor versions until the API and safety model stabilize at `1.0.0`.

Legend: ✅ done · 🚧 in progress · ⬜ planned

## v0.1 — Scaffold ✅
Deterministic core proven end-to-end for recon.
- ✅ Structured state model + JSON persistence
- ✅ Safety layer: scope, validator, audit
- ✅ Adapter contract + nmap reference adapter
- ✅ Orchestrator loop + Claude planner with offline fallback
- ✅ CLI: `run`, `status`

## v0.2 — Recon & enumeration breadth 🚧
Cover the discovery phase across infra and web.
- ✅ Adapters: `whatweb` · `ffuf` · `nuclei` · `enum4linux-ng`
- ✅ Capability-based tool selection in the planner
- ✅ Phase transitions (recon → enumeration → vuln) driven by state
- ✅ OUTFILE mechanism for file-output tools
- ⬜ `httpx`/service fingerprint enrichment

## v0.3 — Analysis ✅
Turn raw services into leads.
- ✅ Version → CVE mapping (local offline KB; pluggable for a fuller feed)
- ✅ Cross-service correlator (EternalBlue candidate, cleartext/anon FTP, telnet)
- ✅ Finding synthesis with severity + remediation, deduplicated
- ✅ NVD 2.0 feed import (`kb-import`) + `BREACHLOAD_KB` extension point

## v0.4 — Exploitation & payloads 🚧
Generation is unrestricted; delivery is scope- and confirm-gated.
- ✅ `Artifact` state model (generated payloads/PoCs as first-class records)
- ✅ `msfvenom` payload generator (offline, no scope check) + `payload` command
- ✅ Delivery adapters (EXPLOIT risk class → confirmation gate) + `deliver` command
- ✅ Claude-authored PoC scripting for identified CVEs (`poc` command)
- ✅ Kill-switch + rate limiting

## v0.5 — Post-exploitation ⬜
- ⬜ Privilege-escalation enumeration (linpeas-style parsing)
- ⬜ Credential looting into the state model
- ⬜ Lateral-movement suggestions from correlated state

## v0.6 — Reporting ✅
- ✅ State → Markdown report (summary, hosts, findings, creds, artifacts, timeline)
- ✅ PDF export (dependency-free)
- ✅ Reproduction steps pulled from the history

## v0.7 — CTF mode ✅
- ✅ Aggressive defaults, raised auto-threshold (`ctf: true`)
- ✅ Flag detection & auto-capture (into `state.flags`, `flag` events)
- ✅ Flags shown live on the dashboard

## v0.8 — Web dashboard 🚧
Follow and steer an engagement from a browser while the engine runs in the
terminal. Rides on the orchestrator's existing `on_event` seam.
- ✅ FastAPI backend + WebSocket event stream
- ✅ Live phase progress + command feed (what ran, why)
- ✅ Findings panel with severity + host/service view (polls `/api/state`)
- ✅ Confirmation gate in the UI (approve/deny risky actions)
- ✅ Remote view (engine on the box, dashboard on the laptop) + `serve` command
- ✅ Live push of state snapshots over WS (polling is only a fallback)
- ✅ In-UI kill-switch (Stop button → `/api/stop`)

## v1.0 — Stable 🚧
- ✅ Documented plugin interface for third-party adapters (`breachload.tools`)
- ✅ Frozen adapter API and safety-model contract (`CONTRACT.md`)
- ✅ Full test coverage on safety layer (100%)
- ⬜ Beta soak on live HTB/CTF boxes before tagging 1.0.0

See open work on the [issue tracker](https://github.com/Noxiidus/breachload/issues)
and the [project board](https://github.com/Noxiidus/breachload/projects).
