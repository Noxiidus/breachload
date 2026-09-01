# Getting Started

You are five minutes away from your first breachload run. This page assumes
zero prior experience with the tool.

## What breachload does, in one sentence

It runs the boring recon+enumeration for you against a target you own (or a lab
box you're authorized to attack), turns raw tool output into structured findings,
and tells you the next thing worth trying — every action safety-checked against
your allowed scope.

## 1. Install (Linux/WSL Kali, ~1 minute)

```bash
git clone https://github.com/Noxiidus/breachload.git
cd breachload
python3 -m venv ~/bl-venv
~/bl-venv/bin/pip install -e .
```

That's the whole install. Two optional extras if you want them later:

```bash
~/bl-venv/bin/pip install -e '.[web]'       # live web dashboard
~/bl-venv/bin/pip install -e '.[browser]'   # client-side (JS) scanner
```

Sanity check — every internal adapter's command passes the safety validator,
completely offline:

```bash
~/bl-venv/bin/python -m breachload.cli doctor --self-test
```

You should see `+` next to every adapter and `all adapters pass the self-test`.

## 2. Pick a planner backend (optional but recommended)

The planner decides "what should we try next?". Three modes:

- **Heuristic (default, no setup)** - a deterministic rule-based planner. Works
  end-to-end with zero configuration.
- **Claude** - `export ANTHROPIC_API_KEY=sk-ant-...` before running.
- **Local (fully offline)** - point at an Ollama/LM Studio instance:
  ```bash
  export BREACHLOAD_LOCAL_LLM_URL=http://127.0.0.1:11434
  export BREACHLOAD_LOCAL_LLM_MODEL=llama3
  ```

You can flip between them by changing the env vars — no reinstall needed.

## 3. Check your toolchain

```bash
~/bl-venv/bin/python -m breachload.cli doctor
```

Green `+` = tool installed, red `-` = missing. breachload uses whichever tools
you have (nmap, whatweb, ffuf, nuclei, netexec, impacket, evil-winrm, certipy,
sshuttle, chisel, …) and skips the rest gracefully. Missing tools = fewer
findings, never a crash.

`doctor --install` prints a copy-paste line per missing tool.

## 4. Your first run (~2 minutes on an Easy HTB box)

```bash
# Create a config file for your target
cat > engagements/first.yaml <<YAML
name: first
mode: full-auto
ctf: true
targets:
  - 10.10.10.5
  - firstbox.htb
auto_threshold: active
lhost: 10.10.14.10        # YOUR attacker IP (`ip a show tun0`)
YAML

# Run recon -> enumeration -> vuln analysis end-to-end
~/bl-venv/bin/python -m breachload.cli run engagements/first.yaml --stop vuln
```

You'll see a live stream of what it's doing: port scan, service detection,
web fingerprinting, subdomain fuzzing, known-CVE mapping. Each finding lands
in the structured state.

## 5. See what it found

```bash
# What does it know?
~/bl-venv/bin/python -m breachload.cli status engagements/first.yaml

# What should you try next?
~/bl-venv/bin/python -m breachload.cli suggest engagements/first.yaml

# Full report as HTML (open it in a browser)
~/bl-venv/bin/python -m breachload.cli report engagements/first.yaml --html
firefox engagements/first/report.html
```

The `suggest` output ranks the leads: which known CVE to try first, which
default credentials to sweep, which auth-aware paths to fuzz. Every action is
copy-paste ready — breachload never runs an intrusive command without your OK.

## 6. Where to go next

- [Your First Engagement](Your-First-Engagement) - a full walkthrough from
  first port scan to captured flag
- [Command Reference](Command-Reference) - every subcommand with an example
- [Safety Model](Safety-Model) - what breachload will and won't run for you
- [MCP Server](MCP-Server) - use breachload as a tool from Claude Code
