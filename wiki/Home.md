# breachload wiki

The user-facing, tutorial-first documentation. Every page is written so
someone who has never used breachload (or a pentest tool at all) can
follow along.

## Start here

- [Getting Started](Getting-Started) — install, first run, what you'll see
- [Your First Engagement](Your-First-Engagement) — a walkthrough on a lab box
- [Command Reference](Command-Reference) — every CLI command with an example

## By task

- [Recon & Fingerprinting](Recon-and-Fingerprinting) — what breachload maps, how
- [Guided Exploitation](Guided-Exploitation) — from a finding to a shell
- [Post-Exploitation](Post-Exploitation) — loot, privesc, lateral, cloud, pivot
- [Active Directory](Active-Directory) — BloodHound, ADCS, Kerberoast, kill-chain
- [Reporting & Audit](Reporting) — MD/HTML/PDF + tamper-evident audit log

## Concepts

- [Safety Model](Safety-Model) — scope, argv-only, confirm-gates, auto-exploit
- [Architecture](Architecture) — the internal layout
- [State + Findings](State-and-Findings) — the typed record every action writes to
- [Suspected vs Confirmed](Suspected-vs-Confirmed) — the proof model
- [Sessions](Sessions) — webshell / ssh / winrm channels + auto-staging

## Integration

- [MCP Server](MCP-Server) — using breachload from any LLM agent (Claude Code, …)
- [Web Dashboard](Web-Dashboard) — the FastAPI/WebSocket live view
- [Local-first (Ollama / LM Studio)](Local-LLM) — offline planner backend
- [Custom Adapters](Custom-Adapters) — plugin entry-point (also see Writing-Adapters)

## Advanced

- [Auto-Exploit](Auto-Exploit) — the operator-gated autonomous chain
- [Bug-Hunt Workflow](Bug-Hunt) — fuzz, self-test, held-out coverage
- [Live Dogfood](Live-Dogfood) — reproducible per-box scoring
- [Release Process](Release-Process) — version bump → tag → release → README update
