# breachload wiki

The user-facing, tutorial-first documentation. Every page is written so someone
who has never used breachload (or a pentest tool at all) can follow along.

## Start here

- [Getting Started](Getting-Started) - install, first run, what you'll see
- [Your First Engagement](Your-First-Engagement) - a walkthrough on a lab target
- [Command Reference](Command-Reference) - every CLI command, one-line + example

## By task

- [Recon & fingerprinting](Recon-and-Fingerprinting) - what breachload maps, how
- [Guided exploitation](Guided-Exploitation) - taking a lead from fingerprint to a shell
- [Post-exploitation](Post-Exploitation) - loot, privesc, lateral, cloud, pivot
- [Active Directory](Active-Directory) - BloodHound, Kerberoast, ADCS, kill-chain
- [Reporting & audit](Reporting) - MD/HTML/PDF, CVSS, tamper-evident log

## Concepts

- [The safety model](Safety-Model) - scope, argv-only, confirm-gates, auto-exploit
- [State + findings](State-and-Findings) - the typed record every action writes to
- [Suspected vs confirmed](Suspected-vs-Confirmed) - proof-based findings
- [Sessions](Sessions) - webshell / ssh / winrm channels + auto-staging

## Integration

- [MCP server (any LLM agent)](MCP-Server) - Claude Code, Claude Desktop, etc.
- [Live web dashboard](Web-Dashboard) - the FastAPI/WebSocket UI
- [Local-first (Ollama / LM Studio)](Local-LLM) - offline planner backend
- [Extending with a custom adapter](Custom-Adapters) - plugin entry-point

## Advanced

- [Auto-exploit mode](Auto-Exploit) - the operator-gated autonomous chain
- [Bug hunt workflow](Bug-Hunt) - fuzz, self-test, held-out coverage
- [Live dogfood harness](Live-Dogfood) - reproducible per-box scoring
- [Release process](Release-Process) - version bump, tag, release, README update
