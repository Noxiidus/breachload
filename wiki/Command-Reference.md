# Command Reference

Every subcommand in breachload with one line + a real example. Grouped the same
way `breachload --help` shows them (Setup, Recon, Exploitation, Post-ex, Active
Directory, Reporting, Learn).

## Setup & control

| Command | Does |
|---------|------|
| `init` | Interactive wizard: writes a first engagement YAML |
| `run <cfg>` | Auto-chain recon -> enum -> vuln analysis |
| `auto <cfg>` | One shot: run + `suggest` + report |
| `session <cfg> --webshell URL / --ssh U:P@H / --winrm U:P@H` | Register a foothold session |
| `auto-exploit <cfg>` | Authorized autonomous chain (needs operator gate) |
| `serve <cfg>` | Live web dashboard on http://localhost:8000 |
| `doctor` | Which external tools + wordlists are installed |
| `doctor --self-test` | Every registered adapter passes the safety validator |
| `doctor --install` | Print install commands for missing tools |
| `status <cfg>` | Print the current state summary |
| `mcp` | Run breachload as an MCP server on stdio |

**Example:**
```bash
breachload run engagements/mybox.yaml --stop vuln
```

## Recon, enum & planning

| Command | Does |
|---------|------|
| `suggest <cfg>` | Rule-based ranked next-step plan (no API key needed) |
| `secrets --scan file / --text ... / --discover URL` | Secret regex library + content-discovery probes |
| `unauthapi <URL>` | Probe common unauth admin/API endpoints (NiFi/actuator/ES/K8s/Docker/…) |
| `defaultcreds <cfg>` | Argv sweep for default credentials on every detected service |
| `nucleiscan <cfg>` | Full nuclei orchestration: tags + severity + CVE-id passes |
| `browser <URL> [--config cfg]` | Client-side (JS-executed) DOM scan for auth/CSRF/DOM-XSS |
| `authlogin <URL> <user> <pass>` | Login ladder for auth-aware crawl (returns session cookie) |
| `hosts <cfg> --write` | Append discovered vhosts to `/etc/hosts` (confirm-gated) |

**Example:**
```bash
breachload secrets --discover http://target/
breachload unauthapi http://target:8080/
```

## Exploitation

| Command | Does |
|---------|------|
| `payload <cfg> --payload ... --lhost ... --lport ...` | msfvenom generation (offline, not fired) |
| `payloads --tag smb` | Browse the offline payload library |
| `poc <cfg> --finding N` | Claude-authored PoC for a specific finding (or offline template) |
| `deliver <cfg> --artifact NAME --target HOST` | Deliver an artifact against a target (confirm-gated) |
| `sploit <cfg>` | searchsploit per service, mirror the interesting ones |
| `listen <cfg>` | Reverse-shell listener kit (nc/pwncat/msf) with matching payloads |
| `crack <cfg> --run` | Identify + crack every stored hash |
| `flag <cfg> --scan file` | Extract flag(s) from an output file |
| `lfi <URL> <param>` | LFI -> RCE ladder (wrappers, log/session/environ poison) |
| `uploadfuzz <URL>` | Upload-bypass extension matrix + polyglot |
| `deser <cfg> or --fingerprint ...` | Deserialization payloads per stack (ysoserial/phpggc/ysoserial.net) |

**Example:**
```bash
breachload lfi 'http://target/?file=x' file
breachload deser --fingerprint 'Apache Tomcat 9' --cmd 'bash -c id'
```

## Post-exploitation

| Command | Does |
|---------|------|
| `loot <cfg> --scan file` | Parse linpeas/shell output into privesc findings + creds + secrets |
| `privesc <cfg>` | Linux privesc playbook (linpeas/pspy transfer + parse-back) |
| `winprivesc <cfg>` | Windows privesc playbook (winPEAS + parse) |
| `pivot <cfg> --via H --subnet N [--ssh-user U]` | sshuttle/chisel/ligolo/ssh forward commands |
| `lateral <cfg>` | winrm/wmi/psexec/smbexec + PtH per Windows host x usable cred |
| `cloud <cfg> or --provider aws/gcp/azure` | Cloud enum commands per provider |
| `appsecrets <app>` or `--decrypt HEX --key K` | Where + how apps store secrets; built-in NiFi/Laravel decoders |

**Example:**
```bash
breachload pivot engagements/mybox.yaml --via 10.10.11.5 --subnet 172.16.5.0/24
breachload appsecrets nifi
breachload cloud --provider aws
```

## Active Directory

| Command | Does |
|---------|------|
| `bloodhound <cfg> --scan users.json` | Parse BloodHound export into findings |
| `adcs <cfg> --scan certipy.txt` | Parse `certipy find -vulnerable` into ESC1-16 findings |
| `adchain <cfg>` | Ranked path to Domain Admin with the next command per step |
| `kerberos <cfg> --dc IP --domain D --run` | AS-REP roast + Kerberoast (impacket) + parse hashes |
| `creds <cfg> --add user:secret --kind password/hash/key/ticket` | List/add credentials |

**Example:**
```bash
breachload kerberos engagements/mybox.yaml --dc 10.10.11.5 --domain corp.local --run
breachload adchain engagements/mybox.yaml
```

## Reporting & audit

| Command | Does |
|---------|------|
| `report <cfg> [--html] [--pdf]` | Markdown / HTML / PDF report with CVSS + proof status |
| `audit <cfg> --verify` | Verify the tamper-evident hash-chained audit log |

**Example:**
```bash
breachload report engagements/mybox.yaml --html --pdf
breachload audit engagements/mybox.yaml --verify
```

## Learn & knowledge base

| Command | Does |
|---------|------|
| `explain <term>` | Plain-language explanation of a pentest term |
| `gtfo <binary>` | GTFOBins escalation for a SUID/sudo binary |
| `kb-import NVD_FEED` | Grow the CVE knowledge base from an NVD 2.0 JSON feed |

**Example:**
```bash
breachload explain ssti
breachload gtfo find
```

## Universal flags

- `--help` on any subcommand for full options.
- Every subcommand takes the engagement YAML as its first positional argument
  (some accept `--fingerprint` / `--parse-file` alternatives for standalone use).
- Nothing runs an intrusive command without a confirm-gate unless
  `auto_threshold` and the risk class permit it.

See also: [Your First Engagement](Your-First-Engagement) for how these string
together on a real box, and [Safety Model](Safety-Model) for what "confirm-gate"
actually means.
