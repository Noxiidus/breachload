# breachload

Autonomous pentest copilot for Linux & Windows targets. It drives an engagement
from recon to report — runs tools, parses their output into structured state,
decides the next step, composes attack chains, and generates working findings —
while a deterministic safety layer keeps every action inside the authorized scope.

> For authorized security testing, CTF/HTB, and research only. You are responsible
> for having written permission to test every target in scope.

Latest release: **v0.21.0** · CI: ruff + mypy + 838+ tests green.

## What it does

- **Recon → attack-surface map.** Full-port nmap, web fingerprinting (whatweb,
  httpx, a deep `appfinger` signature table), directory + **vhost/subdomain**
  discovery, DNS **AXFR**, and ~20 service adapters (SMB, LDAP, SNMP, the SQL
  family, redis, rsync, …). It maps what's really there — including apps hidden
  behind a subdomain (the thing that makes or breaks a box).
- **Fingerprint → known-CVE lead.** A curated web-app CVE knowledge base turns a
  detected app+version into a named CVE with a **ready, review-then-run exploit
  command** — 35+ apps (FreePBX, GLPI, Metabase, Apache NiFi, Zabbix, …).
- **Generalized detectors, not per-box patches.** A library of *class-level*
  detectors that hit on any box fitting the pattern: **secret-scan** (cloud keys,
  JWT, DB URIs, private keys) + sensitive-content discovery (`.git`, `.env`,
  actuator); **unauth admin/API** detector (Spring actuator, ES, K8s, Docker,
  Vault, NiFi); **default-cred sweep** across services + 30+ web apps;
  **writable-root-path / PATH-hijack / writable systemd unit / SUID root**
  detectors from the shell enum; **GPP cpassword decrypt** with Microsoft's
  public key; **LFI→RCE ladder** + upload-bypass matrix; **deserialization**
  payload commands keyed to stack; **SSRF→cloud IMDS** token extraction.
- **App-config secret extraction library.** 15 app profiles (where + how) with
  built-in NiFi (PBKDF2-AES-GCM) and Laravel (AES-CBC) decoders.
- **Guided exploitation & post-ex.** Auto-foothold modules for several CVEs, a
  session abstraction (webshell / ssh / **WinRM**) with file **upload/staging**,
  autonomous **Linux & Windows privilege escalation** (proven by reading the flag),
  an **AD kill-chain composer** (BloodHound / ADCS / roasting → a ranked path
  to Domain Admin), active **Kerberoast/AS-REP** + autonomous ADCS ESC1 loop, and
  **Windows lateral chains** (winrm/wmi/psexec/smbexec + Pass-the-Hash).
- **Cloud post-ex.** AWS/GCP/Azure enum-command library keyed on held credentials.
- **Nuclei full orchestration.** Tag pass + severity pass + CVE-id pass per HTTP
  service, with a safety-net `-tags cve -severity high,critical` fallback so an
  unknown app still gets a bounded known-CVE sweep. CVSS + `confirmed` on every
  match.
- **Proof, not guesses.** Every finding is `suspected` or **`confirmed`** (with the
  concrete `proof` — a read flag, an opened session, a recovered hash).
- **Reports.** Markdown, self-contained **HTML**, and PDF — with CVSS, an
  executive summary, confirmed-vs-suspected counts, and a **tamper-evident,
  hash-chained audit log** (`breachload audit --verify`).
- **Composable.** An **MCP server** (14 tools) exposes breachload's safe,
  deterministic surface — fingerprint→CVE, AD kill-chain, next-step planner,
  suggest, render-report, secret-scan, default-creds, privesc-classes, and more —
  to any LLM agent (Claude Code, …). A **client-side browser scanner** (Playwright)
  covers the DOM surface a curl scan can't see.
- **Local-first optional.** Set `BREACHLOAD_LOCAL_LLM_URL` to run the planner
  through Ollama / LM Studio / any OpenAI-compatible endpoint — fully offline.

## Design

- **Deterministic core, LLM only for decisions.** Parsing, state, and scope are
  code. The model (Claude, optional) only picks the next action and explains why —
  it never parses raw output and never bypasses the safety layer. With no API key,
  a heuristic planner still drives the whole pipeline (fully testable offline).
- **Structured state, not chat history.** Every host / service / credential /
  finding is a typed record (`core/state.py`), queryable and reproducible.
- **Safety layer is the spine of full-auto** (`safety/`): a hard scope allowlist,
  command validation (binary allowlist + **no shell metacharacters** — argv only,
  so no injection), and a risk classifier that forces confirmation on
  intrusive/exploit/destructive actions. An opt-in, operator-gated, audited
  **auto-exploit** mode removes the prompt up to exploitation for authorized scopes
  — scope stays absolute, destructive still asks a human, everything is logged.

## Install

```bash
pip install -e .                     # core
pip install -e '.[web]'              # + FastAPI/WebSocket dashboard
pip install -e '.[browser]'          # + Playwright client-side scanner
playwright install chromium          # (browser extra only)

# Planner backends (pick one; heuristic runs with neither):
export ANTHROPIC_API_KEY=...                       # Claude
export BREACHLOAD_LOCAL_LLM_URL=http://127.0.0.1:11434       # Ollama (default)
export BREACHLOAD_LOCAL_LLM_URL=http://127.0.0.1:1234/v1     # LM Studio / OpenAI-compat
export BREACHLOAD_LOCAL_LLM_MODEL=llama3                     # model name

breachload doctor                    # what tools/wordlists are installed
breachload doctor --self-test        # every adapter passes the validator (offline)
```

## Usage

Commands are grouped in `breachload --help` (Setup · Recon · Exploitation ·
Post-exploitation · Active Directory · Reporting · Learn).

```bash
# Recon → plan → report
breachload run engagements/example.yaml            # auto-chain recon → enum → vuln
breachload auto engagements/example.yaml           # one shot: run + rule-based plan + report
breachload suggest engagements/example.yaml        # rule-based next steps (no API key)
breachload status engagements/example.yaml

# Active Directory
breachload bloodhound <cfg> --scan users.json      # BloodHound → findings
breachload adcs <cfg> --scan certipy.txt           # ESC1-16 findings + certipy commands
breachload adchain <cfg>                            # ranked path to Domain Admin
breachload kerberos <cfg> --dc 10.10.11.5 --domain corp.local --run

# Recon (generalized detectors, work on ANY box fitting the class)
breachload secrets --scan looted.txt                # cloud keys / JWT / DB URIs / private keys
breachload secrets --discover http://target/        # .git / .env / actuator / backups probes
breachload unauthapi http://target/                 # NiFi/actuator/ES/K8s/Docker/... probes
breachload defaultcreds <cfg>                       # default-cred sweep across all services
breachload nucleiscan <cfg>                         # tags + severity + CVE-id passes
breachload browser https://app.example.com          # client-side DOM scan
breachload authlogin http://x/ alice pass           # login ladder for auth-aware crawl

# Post-exploitation
breachload session <cfg> --winrm user:pass@host    # register a foothold (webshell/ssh/winrm)
breachload loot <cfg> --scan linpeas.txt           # privesc + creds + secret-scan from loot
breachload privesc <cfg> / winprivesc <cfg>        # Linux / Windows privesc playbooks
breachload pivot <cfg> --via 10.10.11.5 --subnet 172.16.5.0/24
breachload lateral <cfg>                            # winrm/wmi/psexec/smbexec + PtH per host
breachload cloud <cfg>                              # AWS/GCP/Azure enum for held creds
breachload appsecrets nifi                          # where + how apps store secrets
breachload deser <cfg>                              # ysoserial/phpggc/ysoserial.net per stack
breachload lfi http://x/?p=x p                      # LFI->RCE ladder
breachload uploadfuzz http://x/upload               # upload-bypass extension matrix
breachload crack <cfg> --run                        # identify + crack stored hashes

# Reporting
breachload report <cfg> --html --pdf               # MD + HTML + PDF, with CVSS + proof status
breachload audit <cfg> --verify                    # verify the tamper-evident audit chain

# Composability
breachload mcp                                      # run as an MCP server (stdio)
breachload browser https://app.example.com --config <cfg>   # client-side DOM scan
```

See [docs/MCP.md](docs/MCP.md) for the MCP server, [docs/AUTO-EXPLOIT.md](docs/AUTO-EXPLOIT.md)
for the authorized auto-exploit mode, [docs/SETUP.md](docs/SETUP.md) for a fresh-VM
setup, and [WALKTHROUGH.md](WALKTHROUGH.md) for a full box start to finish.

## MCP server

`breachload mcp` speaks the Model Context Protocol over stdio (JSON-RPC), exposing
breachload's **safe, deterministic** surface to any agent (Claude Code, …). It
**never fires at a target** and never bypasses scope/validator: the agent drives,
breachload contributes the trustworthy reviewed pieces. See [docs/MCP.md](docs/MCP.md).

The 14 exposed tools cover both lookup and planning/reporting:

| Group | Tools |
|-------|-------|
| Lookup | `fingerprint_to_cve`, `identify_hash`, `gtfobins`, `explain_term`, `parse_nmap_xml`, `parse_roast` |
| Planning | `ad_killchain`, `pivot_plan`, `next_step`, `suggest`, `default_creds` |
| Detection | `secret_scan`, `privesc_classes` |
| Reporting | `render_report` |

Quick registration for Claude Code:

```bash
claude mcp add breachload -- breachload mcp
```

## Live dogfood

See [docs/DOGFOOD.md](docs/DOGFOOD.md) for the reproducible per-box workflow: one
line per box into [docs/dogfood-scores.csv](docs/dogfood-scores.csv), score on
recon-coverage / guided-fit / autonomous-hit. Held-out coverage tests live under
`tests/held_out/` (opt in with `pytest -m held_out`) so a class fix that helps one
box gets asserted across the whole set going forward.

## Extending

- Grow the web-app CVE KB (`data/webapp_kb.json`) or import CVEs from an NVD feed
  (`breachload kb-import`).
- Add your own scanners via the `breachload.tools` entry-point group — a broken
  plugin is logged and skipped; built-ins are never shadowed.

## Layout

```
breachload/
  core/        orchestrator, state, config, llm planner, session, netutil, audit-chain
  safety/      scope, validator, tamper-evident audit
  tools/       ~23 run+parse adapters (nmap is the reference)
  analysis/    CVE mapping, correlator, AD kill-chain, Kerberos, privesc, pivot, browser
  exploit/     auto-foothold modules, payload generation + delivery, PoC, library
  data/        web-app CVE KB + offline payload/technique library
  report/      findings → markdown / HTML / PDF + CVSS scoring
  mcp/         MCP server (stdio JSON-RPC)
  web/         FastAPI + WebSocket dashboard
engagements/   per-engagement scope + state + audit log
```
