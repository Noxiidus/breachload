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
- 🚧 Adapters: ✅ `whatweb` · ✅ `ffuf` · ✅ `nuclei` · ⬜ `enum4linux-ng`
- ⬜ Capability-based tool selection in the planner
- ⬜ Phase transitions (recon → enumeration → vuln) driven by state
- ⬜ `httpx`/service fingerprint enrichment

## v0.3 — Analysis ⬜
Turn raw services into leads.
- ⬜ Version → CVE mapping (local NVD/Vulners cache, offline-friendly)
- ⬜ Cross-service correlator (e.g. SMBv1 + Windows → EternalBlue candidate)
- ⬜ Finding synthesis with severity + remediation

## v0.4 — Exploitation & payloads ⬜
Generation is unrestricted; delivery is scope- and confirm-gated.
- ⬜ `Artifact` state model (generated payloads/PoCs as first-class records)
- ⬜ `msfvenom` payload generator adapter (offline, no scope check)
- ⬜ Claude-authored PoC scripting for identified CVEs
- ⬜ Delivery adapters (EXPLOIT risk class → confirmation gate)
- ⬜ Kill-switch + hard rate limiting

## v0.5 — Post-exploitation ⬜
- ⬜ Privilege-escalation enumeration (linpeas-style parsing)
- ⬜ Credential looting into the state model
- ⬜ Lateral-movement suggestions from correlated state

## v0.6 — Reporting ⬜
- ⬜ Findings → Markdown report (Jinja2)
- ⬜ PDF export
- ⬜ Reproduction steps pulled from the audit log

## v0.7 — CTF mode ⬜
- ⬜ Aggressive defaults, raised auto-threshold
- ⬜ Flag detection & auto-capture
- ⬜ Lightweight per-box reporting

## v0.8 — Web dashboard ⬜
Follow and steer an engagement from a browser while the engine runs in the
terminal. Rides on the orchestrator's existing `on_event` seam.
- ⬜ FastAPI backend + WebSocket event stream
- ⬜ Live phase progress + command feed (what ran, why)
- ⬜ Target map: host → service → finding tree, built live from state
- ⬜ Findings panel with severity
- ⬜ Confirmation gate in the UI (approve/deny risky actions with one click)
- ⬜ Read-only remote view (engine on the box, dashboard on the laptop)

## v1.0 — Stable ⬜
- ⬜ Frozen adapter API and safety-model contract
- ⬜ Full test coverage on safety layer
- ⬜ Documented plugin interface for third-party adapters

See open work on the [issue tracker](https://github.com/Noxiidus/breachload/issues)
and the [project board](https://github.com/Noxiidus/breachload/projects).
