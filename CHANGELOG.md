# Changelog

All notable changes to breachload are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.0] - 2026-08-23

### Added
- **Auto-foothold modules** (`exploit/footholds.py`) — the piece that makes the chain fully
  autonomous: in the auto-exploit EXPLOIT phase, a coded module for a matching KB CVE fires the
  real exploit, gains code execution, and hands back a live **Session** for the POST phase. Ships
  the **FreePBX CVE-2025-57819** module (SQLi stacked-write of a `cron_jobs` webshell dropper ->
  waits for cron -> registers a webshell session). Unlike the read-only probes these *write* to the
  target, so they run only in auto-exploit mode, are scope-checked, and audited. **Verified live on
  HTB Connected: the engine autonomously established the foothold and opened the session.**
- More autonomous privesc vectors: **cap_setuid on a scriptable interpreter** (python/perl/ruby/node
  -> `setuid(0)` then read the proof) joins full-sudo / sudo-NOPASSWD / docker-group / SUID-shell.
- **Container / orchestration escape detection** in `loot` (`postexploit.parse_container`): flags a
  writable Docker socket, a mounted Kubernetes service-account token, and a privileged container
  (`.dockerenv` + `CAP_SYS_ADMIN`), each with the escape command.
- **BloodHound ingestion** (`analysis/bloodhound.py` + `bloodhound` command): parses BloodHound /
  SharpHound / bloodhound-python JSON into AD findings — kerberoastable & AS-REP-roastable accounts,
  unconstrained delegation, and dangerous outbound ACL edges (GenericAll/WriteOwner/…) — each with
  the concrete impacket/bloodyAD follow-up.

## [0.14.0] - 2026-08-23

### Added
- **Autonomous, session-driven privilege escalation** (`core/session.py`, `analysis/privesc_auto.py`,
  `session` command) — the piece that makes auto-exploit a full autonomous chain once a foothold is
  in hand. A **Session** is a command-execution channel to an already-compromised, in-scope host:
  **webshell** (a URL with a `FUZZ` marker, run via curl) or **ssh** (user:pass@host via sshpass /
  key). `breachload session <cfg> --webshell '...FUZZ' | --ssh user:pass@host` registers it
  (scope-checked, `--test` runs `id`). In the auto-exploit POST phase the engine then autonomously
  runs the privesc enumeration through the session (`id`, `sudo -l`, SUID sweep, `getcap`, cron),
  parses it with the existing `loot` parsers, and fires a curated escalation — full sudo, sudo
  NOPASSWD on a scriptable binary, or the `docker` group — proving root by reading `/root/root.txt`.
  Escalation is bounded to well-understood vectors that read the proof file, not arbitrary
  persistence; the session host is scope-checked and every command is audited. The curated
  escalations cover full sudo, sudo NOPASSWD on a scriptable binary, the `docker` group, and a
  root-owned SUID shell. Verified live on HTB Connected: it autonomously enumerated the foothold
  through the webshell session and parsed SUID/capability findings.

## [0.13.0] - 2026-08-23

### Added
- **FreePBX -> CVE-2025-57819** in the web-app CVE KB (endpoint-module unauthenticated SQLi -> RCE,
  incron/`sysadmin_manager` root chain), with a **read-only** auto-fire probe that confirms the SQLi
  via an error-based `EXTRACTVALUE(USER())` GET — so the auto-exploit mode autonomously *confirms* the
  vulnerability while the webshell/RCE step stays guided. Grounded in a live HTB dogfood (Connected).
- **Auto-exploit firing engine** (`exploit/autofire.py`, `tools/exploitprobe.py`): in the EXPLOIT
  phase the engine autonomously fires a curated set of **read-only** KB-CVE probes (Grafana LFI,
  Joomla config leak, ownCloud phpinfo, Metabase setup-token, Nginx UI) as single validated `curl`
  argv commands, and folds any disclosed credentials / flags into state. RCE, write, and command-
  injection exploits are deliberately **never** auto-fired — they stay surfaced as guided commands,
  so the injection guard holds and autonomous action is bounded to disclosure. Reached via the
  auto-exploit walk (or an explicit `--phase exploitation`, still EXPLOIT-risk-gated).
- **Beginner / learner mode** (`docs/BEGINNER-ROADMAP.md`):
  - `breachload init` — interactive wizard that writes the engagement YAML (with a first-run
    authorization checklist), so no hand-editing is needed.
  - `breachload explain <term>` — offline glossary (SSTI, kerberoast, ESC1/ESC9, shadow-creds,
    DCSync, SUID, GTFOBins, pivoting, JWT, …): what it is / why it matters / what breachload does.
  - `run --dry-run` — preview the commands the engine would run, without touching the target.
  - `doctor --install` — print the exact install command for each missing tool.
  - **Attack-path narrative** in the report — a plain-language story (recon → foothold leads →
    credentials → privesc → flags) that turns a solved box into a study document.
- **Auto-exploit mode** (`breachload auto-exploit`, `core/authz.py`, `docs/AUTO-EXPLOIT.md`): an
  opt-in, authorized, audited mode that walks an engagement autonomously through exploitation and
  post-exploitation without per-action confirmation. Gated on three independent conditions — the
  engagement's `auto_exploit: true` + `authorized: true` flags AND an operator that passes the
  operator allowlist (`$BREACHLOAD_OPERATOR`/`$BREACHLOAD_TOKEN` vs a git-ignored operators file,
  constant-time token compare). The invariants hold even here: scope stays absolute (off-scope
  hard-blocked), DESTRUCTIVE actions still require a human, the injection guard is intact (only
  validated argv runs, never a shell), and the authorization + every action are written to the
  audit log. Fails closed with a specific reason when any condition is missing.

### Fixed
- Safety-blocked / user-declined actions were recorded to persistent history and counted by
  `has_action`, so a target that was out-of-scope on one run (then added to scope) would be skipped
  on the next. The orchestrator now prunes those (approved=False, no exit code) at the start of each
  run, while executed actions and permanent build-failures persist. Found via a live HTB dogfood.

## [0.12.0] - 2026-08-23

### Added
- Four more service adapters (registry now 20): **ldap** (anonymous bind -> naming contexts +
  domain tag), **rpc** (`rpcinfo` portmapper dump), **rsync** (unauthenticated module listing),
  **mongodb** (unauth `listDatabases` via mongosh). Wired into the enum heuristic + `doctor`.
- **nuclei auto-tagging**: the planner maps a service's detected stack (WordPress/Grafana/Jenkins/…)
  to nuclei `-tags`, so the vuln scan runs the relevant template set instead of everything.
- **Auth-aware re-crawl**: ffuf gains a `cookie` option, and once credentials exist the web
  attack-surface suggestion names the cookie-driven re-fuzz of content behind the login.
- **Windows local privilege-escalation** (`analysis/winprivesc.py` + `winprivesc` command): a
  winPEAS/PrivescCheck transfer+run playbook, plus parsers for token privileges (SeImpersonate ->
  potato, SeBackup, SeRestore, …), AlwaysInstallElevated (with an msi payload command), unquoted
  service paths, and autologon credentials.
- **Ranged fingerprint**: `doctor --target` now also fingerprints a *stalling* endpoint via a tiny
  `Range: bytes=0-4096` GET (Server/X-Powered-By/title) — the response that still returns when a
  full GET hangs on MTU. (`netprobe.ranged_fingerprint`.)
- **Cloud (IMDS) credential parsing** in `loot`: AWS role credentials (AccessKeyId/SecretAccessKey/
  session token, JSON or `AWS_*` env form) are folded into the credential store — the payoff of an
  SSRF -> instance-metadata chain.
- **Dangling ADCS template detector** (`adcs.parse_dangling_templates`): flags templates the CA
  publishes but that have no defined template object — a recreatable-object path to a bespoke ESC1.
- Modern Active Directory: **ADCS ESC parsing** (`analysis/adcs.py` + `adcs` command) folds
  `certipy find -vulnerable` output into per-template ESC1-ESC16 findings, each with the concrete
  `certipy req`/`account update` exploit command; and three new attack chains — **ESC9/ESC16**
  (no-security-extension UPN swap), **Shadow Credentials** (msDS-KeyCredentialLink via certipy
  shadow / pyWhisker + PKINIT), and **ACL abuse** (BloodHound edges -> bloodyAD).
- **searchsploit / Exploit-DB integration** (`analysis/searchsploit.py` + `sploit` command):
  turns each versioned service into a searchsploit query, parses the JSON hits, and records one
  finding per service with the top Exploit-DB titles, their CVEs, and a `searchsploit -m` mirror
  command. Offline-graceful when the binary is absent.
- **Reverse-shell handler kit** (`analysis/handler.py` + `listen` command): a full catch kit -
  listener options (rlwrap-nc / pwncat / penelope / msf), a payload HTTP server, target-side
  fetch+exec and direct reverse-shell one-liners (LHOST/LPORT filled), and PTY-upgrade steps.
  `--run` optionally launches the netcat listener.

### Fixed
- ADCS ESC parsing counted an `ESC<n>` token found in a template's description prose, not only
  under its `[!] Vulnerabilities` section — a false positive; now requires the vulnerabilities
  section. (`docs/BUGHUNT-2026-08-23.md` BUG-1.)
- Web-CVE version detection could borrow a *neighbouring* product's version (`grafana, apache
  2.4.1` -> grafana 2.4.1) from too wide a search window; the window now stops at `,`/`;` and is
  shortened so a version is only taken when it directly follows the app token. (BUG-2.)

## [0.11.0] - 2026-08-23

### Added
- Web attack-surface probes (`analysis/webattacks.py`): for every HTTP host, `suggest`/`auto`
  now name the core injection classes to test with first-probe payloads — SSTI (`{{7*7}}` +
  per-engine RCE), SQLi (login bypass, sqlmap, INTO OUTFILE webshell), LFI (traversal, php
  filter/wrapper, log poisoning), file upload, command injection, SSRF **incl. cloud metadata
  (AWS/GCP IMDS)**, XXE, and JWT (alg:none / HS256 crack). Curated from recurring HTB/CTF
  writeup patterns; light and confirm-gated, not auto-fired.
- Group-membership privesc parsing in `loot` (`postexploit.parse_groups`): flags membership of
  the `docker`, `lxd`/`lxc`, `disk`, or `adm` group and carries the exact root primitive as a
  guided exploit (e.g. `docker run -v /:/mnt ... chroot /mnt`).
- Web-application version → CVE mapping with **guided exploitation** (`analysis/webcve.py`
  + `data/webapp_kb.json`): scans the web fingerprint (product/name/banner **and** the
  service notes where whatweb/httpx put app tech) for a known web app, range-matches its
  version when discoverable, and attaches a ready-to-run, confirm-gated exploit command to
  the finding. Closes the gap where a fingerprinted app (Grafana, Gitea, Confluence, Jenkins,
  Nginx UI, …) was never mapped to a CVE. whatweb now also emits `webapp: <Name> <version>`
  notes so the matcher can range-match. The guided command surfaces in `suggest`/`auto` and
  in the report; a new `Finding.exploit` field carries it. Grow the KB via `BREACHLOAD_WEBAPP_KB`.
- Database and mail enumeration adapters, wired into the enumeration heuristic and `doctor`:
  **mysql** (blank/weak `root` login via the `mysql` client), **postgres** (trust/blank
  `postgres` login via `psql -w`), **mssql** (blank `sa` login via `nxc mssql`, carries a
  guided `xp_cmdshell` command), **smtp** (VRFY username enumeration via `smtp-user-enum`).
  Each is a single-binary, non-interactive probe (one auth attempt, ACTIVE risk) that
  degrades gracefully when its tool/list is missing.
- Linux privilege-escalation enumeration playbook (`analysis/privesc_enum.py` + `privesc`
  command): copy-paste-ready, LHOST-filled commands to stabilize a shell, triage
  SUID/sudo/caps/cron, transfer + run linpeas/pspy from your box, and feed the output back
  to `loot` (which names the escalation via the kernel suggester + GTFOBins). The
  "once you have a shell" suggestion now drives this whole flow instead of a few loose one-liners.
- Network robustness: `doctor --target <ip>` probes the path for the VPN MTU / large-response
  stall (small ranged GET vs full GET) that silently empties web fingerprints, and prints the
  `ip link set tun0 mtu 1300` fix; a new `hosts` command lists /etc/hosts entries for discovered
  virtual hosts and, with `--write`, appends the missing ones (privileged, confirm-gated).
- Hash cracking + credential-reuse loop (`analysis/hashcrack.py` + `crack` command):
  identifies a hash type (bcrypt/sha-crypt/md5crypt/NTLM/NetNTLMv2/Kerberos/phpass/…) by
  prefix and shape, prints ready hashcat + john rockyou commands, and with `--run` cracks
  it and writes the plaintext back as a validated credential — which the existing
  lateral-movement suggestions then reuse across hosts/services. Runs over an explicit
  `--hash` or every stored hash-kind credential.
- Recon depth: `udp_scan` (a top-ports `nmap -sU` pass after the TCP sweep — surfaces
  SNMP/DNS/TFTP/IKE; needs root, skipped gracefully otherwise, and the planner asks for it
  exactly once per host) and `ffuf_recursion`/`recursion_depth` (recurse content discovery
  into found directories). Both threaded from the engagement config through the planner.
- Non-web service-enumeration adapters, wired into the enumeration heuristic and
  `doctor`: **snmp** (`snmpwalk`, community `public` → sysDescr/name + credential-
  looking OIDs), **nfs** (`showmount -e` → exports, flags world-readable), **ftp**
  (anonymous login via `curl`, records the anon credential), **redis** (`redis-cli
  INFO` → unauthenticated access, flagged HIGH). Each degrades gracefully if its
  tool is missing.
- Recon depth: the `full_ports` engagement option (auto-on in CTF mode) makes recon
  scan all 65535 TCP ports (`nmap -p-`) so services on high ports aren't missed; and
  `web_extensions` (e.g. "php,txt,html") makes ffuf also fuzz file extensions. The
  planner threads both from the engagement config.
- Kernel-exploit suggester (`analysis/kernelexploits.py`): `loot` now reads the kernel
  version from `uname`/linpeas output and *proactively* suggests applicable local-root
  exploits by version range (Dirty Pipe, nf_tables CVE-2024-1086, OverlayFS, GameOver(lay),
  Dirty COW) — even when the scanner didn't name the CVE. Ubuntu-only exploits are
  distro-gated, and every finding carries a distro-backport "verify first" caveat.
- Virtual-host / subdomain fuzzing (`tools/vhostfuzz.py`): when enumeration knows a
  named domain vhost (e.g. `paperwork.htb`), it fuzzes `Host: FUZZ.<domain>` against
  the in-scope server (ffuf, auto-calibrated) and records every vhost that answers
  differently, upserting it as a host so the planner enumerates it next. All requests
  go to the in-scope host; the `*.<domain>` scope entry authorizes the discovered
  names. `doctor` now checks the DNS subdomain wordlist.

### Fixed
- Fingerprinting no longer stalls on a slow or streaming root: `whatweb` runs with
  bounded open/read timeouts, and an empty exit-0 result is reported as "connected
  but no data (root may hang or stream)" instead of a bare miss.
- Web enumeration silently found nothing against a live web box (dogfooding).
  Three compounding bugs, all fixed with tests (incl. an end-to-end ffuf test
  through `run()` — the parse()-only unit test could not catch the OUTFILE bug):
  - **ffuf produced zero results.** `-s` + `-o /dev/stdout` makes ffuf emit plain
    text, not JSON; and the OUTFILE round-trip mismatched (ffuf's `-o PATH` writes
    exactly `PATH`, but the framework read `PATH`+suffix). ffuf now routes JSON to
    `{OUTFILE}` with an empty suffix. Added `-ac` so a host that blanket-redirects
    every path no longer reports the whole wordlist as "found".
  - **whatweb dropped the redirect target.** A 301 to a named virtual host now
    records that host + its HTTP service (so the planner pivots enumeration to it)
    and raises a finding flagging the `/etc/hosts` requirement.
  - **recon seeded dead hosts** for unresolvable hostnames; they're now scope-only.
- `httpx`: the "no JSON" note now names the ProjectDiscovery-vs-python-client
  name collision, and `doctor` lists httpx.
- More issues surfaced by continued dogfooding, fixed with tests:
  - The engagement YAML's `lhost`/`lport` were silently ignored, so `suggest`
    and `auto` rendered payloads with a literal `LHOST`. They're now config
    fields; a `--lhost`/`--lport` flag still overrides per-invocation.
  - The pivot suggestion counted an IP and its virtual host as two hosts and
    proposed internal-network tunneling on a single-machine web box. It now
    counts distinct machines (collapsing names that resolve to the same IP).
  - Report reproduce/timeline commands leaked the internal `{OUTFILE}` marker;
    they now render a readable `output.json` path.

## [0.10.0] - 2026-08-15

### Added
- Active Directory capability. The correlator detects a Domain Controller
  (Kerberos + LDAP) and extracts the domain from the LDAP service info; the
  suggestion engine then surfaces the full AD playbook as attack chains, with the
  looted username / password / domain auto-filled: unauthenticated enumeration
  (netexec/nxc, RID cycling, AS-REP), authenticated enum + BloodHound collection,
  Kerberoasting / AS-REP roasting, ADCS abuse (certipy ESC1–16), ACL abuse /
  DCSync (secretsdump, bloodyAD), and password spraying. New `ad` payload-library
  entries (nxc, bloodhound-python, certipy, impacket, evil-winrm, bloodyAD) and
  chain conditions (`has_credentials`, `{USER}`/`{PASS}`/`{DOMAIN}` placeholders).
  `doctor` now reports the AD toolchain. Fully offline / no-API.
- netexec (`nxc`) adapter (`tools/netexec.py`): parses `nxc smb` output into state
  — NetBIOS name, OS, SMB signing, and the AD domain (which lights up DC detection
  and the AD chains); authenticated runs capture valid credentials (with a
  `Pwn3d!` → admin finding) and readable shares. Registered and run in the
  enumeration heuristic before enum4linux.
- Pivoting / tunneling suggestions: when 2+ hosts are in scope, `suggest`/`auto`
  propose tunneling through the foothold to reach the internal network (chisel,
  ligolo-ng, SSH dynamic/local forwards, sshuttle, proxychains).
- `creds` command + credential store: list, or `--add 'user:secret'` a credential
  that then auto-fills the AD / lateral-movement / pivot chains.
- Web-app capability: WordPress detection (from whatweb/httpx tech in notes) fires
  a `wpscan` chain; new library entries for nikto, feroxbuster, gobuster vhost and
  git-dumper, added to the HTTP service suggestion.
- Linux privilege-escalation parsing in `loot`: file capabilities (`cap_setuid`
  etc. → HIGH, GTFOBins-linked) and curated local-privesc CVEs a scanner mentions
  (PwnKit, Baron Samedit, Dirty Pipe, Dirty COW, OverlayFS, sudo `-u#-1`).
- Service enumeration for the classic non-web surfaces: SNMP (onesixtyone +
  snmpwalk), SMTP (user enumeration + open-relay test), NFS/RPC (showmount +
  rpcclient), and anonymous LDAP dump.

### Fixed
- Report reproduction-step attribution used only a trailing-digit guard, so a
  finding on `10.10.10.5` pulled in commands that targeted `210.10.10.5`
  (leading-digit collision). It now guards both sides, matching `has_action`.
- The web dashboard's `/api/state` and `/api/report` returned a raw HTTP 500 on a
  corrupt or truncated `state.json` (e.g. an interrupted pre-atomic-save file).
  The server's `_load_state` now degrades to an empty state / "no state" report,
  matching the CLI's graceful corrupt-state handling.
- nmap parsing fell back to the `<address>` MAC element when a host had no IPv4,
  keying state by a MAC (`AA:BB:CC:...`) — not a scannable target — for an
  ARP-style result. It now prefers IPv4, then IPv6, and skips a MAC-only host.
  IPv6 hosts are parsed instead of dropped.

### Security
- Scope-enforcement gap: a URL's `userinfo` (`http://user:pass@host/`) shadowed
  the real host — `extract_targets` captured the credential part and stopped at
  the first `:`, so an out-of-scope host could pass the scope gate behind an
  in-scope-looking credential (`http://in.scope:x@evil.com/` was allowed while it
  actually contacted `evil.com`). Userinfo is now skipped and the true host
  (including a bracketed IPv6 `[::1]`) is extracted and scope-checked.
- An IPv6 target was never extracted from a command — `extract_targets` only knew
  IPv4 and hostnames — so an out-of-scope IPv6 host slipped through scope entirely
  (`nmap 2001:db8::1` was allowed under an unrelated scope). A bare/bracketed IPv6
  literal argument is now extracted and validated like any other target.

## [0.9.1] - 2026-08-05

Patch release: the hardening from the pre-live-run review passes, on top of
`0.9.0` — no new features, all correctness and robustness.

### Changed
- Config robustness: `auto_threshold` and `mode` are validated when the
  engagement YAML loads (fail-fast with a clear message listing the valid
  values), and every CLI command now reports a missing file, malformed YAML, or
  an invalid field as a clean one-line error and exit code 2 instead of a raw
  Python traceback. The `--phase` error also escapes the offending value so it
  can't be misread as console markup.

### Fixed
- A CIDR/glob-only scope (e.g. `targets: ["10.10.10.0/24"]`) seeds no hosts and
  there is no auto host-discovery, so a run silently did nothing. `run`/`auto`
  now warn clearly instead of exiting quietly.
- Non-ASCII punctuation (em dashes, arrows) in CLI output rendered as a
  replacement char on the Windows cp1250 console — including the `breachload -`
  branding line. All CLI output is now ASCII; the Markdown/PDF report keeps its
  Unicode.
- `Host.upsert_service` merged service notes through a `set`, scrambling their
  order non-deterministically (hash-seeded), so the same engagement re-run
  produced differently-ordered reports. Now an order-preserving dedup — reports
  are reproducible.
- The PDF report rendered em/en dashes, curly quotes and ellipses as `?` (not in
  latin-1); they are now transliterated to ASCII, so the PDF is clean while the
  Markdown keeps its Unicode.
- A corrupt or hand-edited `state.json` produced a raw traceback on every
  command; loading is now wrapped (`_load_state`) with a clean message + exit 2.
- State is saved atomically (temp file + rename), so a crash or Ctrl-C mid-save
  can't leave a truncated `state.json` that breaks resuming an engagement.
- The web dashboard no longer hangs the engine: if the last client disconnects
  with a confirmation pending, it is denied (`cancel_pending`).
- The `serve` background engagement reports a crash to the dashboard instead of
  vanishing into an unretrieved task, and always saves state on exit.
- A failure in the hand-rolled PDF writer no longer loses the report — the
  Markdown is already saved, so a PDF error is a warning, not a crash.
- The exploit-runner timeout path (a hanging delivered exploit) is now covered by
  a test.

## [0.9.0] - 2026-08-03

This release brings the actual version number in line with the code: everything
from exploitation through the web dashboard (roadmap milestones v0.4–v0.8, plus
the v1.0 plugin/contract work) had landed on `main` but sat unreleased behind the
`0.3.0` tag. It is cut as a single `0.9.0`; only the live-box beta soak remains
before `1.0.0`.

### Added
- Startup banner (`banner.py`): pure-ASCII `breachload` wordmark with a "by
  Noxidus" line, shown on interactive runs. Suppressible via `--no-banner` or
  `BREACHLOAD_NO_BANNER=1`; never printed to pipes or scripts.
- Post-exploitation (`analysis/postexploit.py`, `loot` command): parse collected
  shell output (`sudo -l`, a SUID sweep, linpeas, config files) into findings and
  credentials. Passwordless-sudo and known-SUID binaries become privesc findings
  cross-referenced with GTFOBins; passwords, hashes, private keys and URL creds
  are looted into the state model.
- Lateral-movement suggestions: when credentials exist, `suggest`/`auto` propose
  reuse across hosts and services (credential spray, pass-the-hash, SSH/RDP with
  the looted creds).
- `httpx` adapter: HTTP service fingerprint enrichment (status, title, web
  server, detected technologies) folded into the matching service.

### Fixed
- Pre-live-run review pass:
  - `has_action` (planner de-duplication) matched a numeric needle as a prefix of
    a longer one, so enumerating `host:8080` marked `host:80` as already done (and
    host `10.10.10.5` shadowed `10.10.10.50`). A trailing-digit guard keeps them
    distinct — a real correctness bug on boxes with multiple web ports.
  - nuclei's `classification.cve-id` is sometimes a bare string, not a list; it
    was iterated character by character into a bogus CVE list. Now normalized.
  - the `httpx` adapter was registered but never selected by the offline heuristic
    planner, so its enrichment never ran without an LLM. Wired into enumeration
    (httpx → whatweb → ffuf).
  - a `build_command` failure recorded the attempt without its target, so a
    misbehaving planner could re-propose the same failing action; the target is
    now recorded so it isn't retried.
- Credential looting no longer misreads `NOPASSWD:` from sudo output as a
  password (a negative-lookbehind guard; `DB_PASSWORD=` still parses).
- Full review pass (bug hunt before the next release):
  - `loot` no longer crashes (`IndexError`) on a malformed sudoers entry whose
    command is a lone `/` — such entries are skipped and valid ones still parse.
  - `run`/`serve`/`auto` accept short phase aliases (`--phase vuln`, `--stop
    enum`) and reject an unknown phase with a clear message instead of a raw
    `ValueError` traceback (the documented `vuln` value now actually works).
  - Flag capture recognizes bare 32-char-hex HTB flags (`user.txt` / `root.txt`)
    when scanning a trusted file/paste (`flag --scan`) or explicit delivery
    output — previously only `flag{...}`-style flags were caught, so real HTB
    flags were missed. Off by default elsewhere to avoid matching MD5 hashes.
  - Web kill-switch (`/api/stop`) now cancels any pending confirmation, so
    stopping can't leave the engine blocked forever on a gate no client answers.
  - `run_engagement` no longer rewinds the phase back to recon when resuming an
    engagement that has advanced past the auto-walk (exploitation/post/report).
  - `deliver_artifact` awaits an async confirmation callback instead of treating
    the coroutine as truthy and delivering unconditionally.
  - Markdown report cells escape `|` and flatten newlines, so a secret/product/
    banner containing a pipe can't break the tables.
  - Reproduction-step attribution uses the same trailing-digit host guard as the
    planner (finding on `10.10.10.5` no longer pulls in `10.10.10.50` commands).
  - EternalBlue correlation matches legacy Windows with word boundaries, so a
    bare `7` in a build number is no longer read as "Windows 7".
  - `has_action` also rejects a leading adjacent digit (`10.10.10.5` no longer
    matches `210.10.10.5`).
  - NVD import truncates long CVE names with an ASCII `...` (cp1250-safe console).
  - Invalid `auto_threshold` in an engagement YAML raises a clear error listing
    the valid risk levels instead of a bare `KeyError`.

## [0.3.0] - 2026-07-28

### Added
- Stable-contract documentation (`CONTRACT.md`): the `ToolAdapter` API, the
  safety model (`Risk`, `Scope`, `Validator`), and the data schemas are now a
  versioned surface — no breaking change without a major bump.
- 100% test coverage of the safety layer (`scope`, `validator`, `audit`);
  `pytest-cov` added to the dev extra.
- NVD import: `breachload kb-import` converts an NVD 2.0 feed into the KB schema
  (`analysis/nvd.py`); point `BREACHLOAD_KB` at the result to grow the CVE
  knowledge base the analyzer uses.
- Plugin interface: third-party `ToolAdapter`s are discovered from the
  `breachload.tools` entry-point group (`tools/registry.py`). Broken plugins are
  logged and skipped; a plugin can never shadow a built-in adapter.
- `WALKTHROUGH.md`: an end-to-end, no-API-key runbook for a single box.

### Security
- Fixed a scope-enforcement gap: a hostname hidden in an SMB/UNC path
  (`//host/share`, `\\host\share`) or carrying a port (`host:port`) was not
  extracted and could pass the scope gate. `extract_targets` now catches these,
  with tests. (Bare-IP and whole-argument hostnames were already covered.)
- `serve` warns when bound beyond localhost, since the confirm/stop endpoints are
  unauthenticated.

## [0.2.0]

### Added
- Attack-chain templates (`data/chains.json`, `analysis/chains.py`): known
  machine profiles (MS17-010 EternalBlue, anonymous FTP, Tomcat manager, SMB
  quick wins, path-traversal→RCE) matched against the state and surfaced as
  top-priority, ready-to-run playbooks in `suggest`/`auto`. Fully offline.
- Offline GTFOBins lookup (`data/gtfobins.json`, `analysis/gtfobins.py`): map a
  SUID/`sudo`-allowed binary to a concrete privesc command. New `breachload gtfo`.
- Environment detection (`core/environment.py`): new `breachload doctor` reports
  which tools and wordlists are installed, so it's clear what will run vs. skip.
- Flag capture from arbitrary output: new `breachload flag --scan/--text` records
  flags (e.g. from a pasted `user.txt`), and `deliver` scans delivery output for
  flags automatically. `deliver --listen` prints the matching listener command.
- `breachload auto` — one-shot autopilot: runs the recon -> enum -> vuln chain,
  then prints the rule-based attack plan and writes a report (Markdown + PDF), in
  a single command. No API key required. State seeding shared via a helper
  (`_load_or_seed_state`) across `run`, `serve`, and `auto`.
- Offline payload/technique library (`data/payloads.json`, `exploit/library.py`):
  35 curated HTB/CTF entries — reverse shells, TTY upgrades, webshells, msfvenom
  specs, file transfer, privilege-escalation checks, and per-service quick wins.
  Placeholder templates ({LHOST}/{LPORT}/{TARGET}/{PORT}) render offline, no API
  key required. New `breachload payloads` command (list / filter / `--show`).
- Rule-based suggestion engine (`analysis/suggest.py`) — "autopilot without an
  LLM": reads the current state (open services + findings) and prints a
  prioritized, copy-paste-ready plan drawn from the library. New `breachload
  suggest` command. CVE findings come first (with the PoC command), then
  per-service quick wins, then post-shell privilege-escalation steps.
- Kill-switch: `Orchestrator.request_stop()` halts the engagement after the
  current action; surfaced as a Stop button on the dashboard (`POST /api/stop`).
- Rate limiting: `min_action_interval` in the engagement config throttles
  target-facing actions (`core/ratelimit.py`, injectable clock/sleep).
- CTF mode (`ctf: true`): aggressive auto-threshold (runs up to exploitation) and
  automatic flag capture — tool output is scanned for common flag formats
  (`analysis/flags.py`) into `state.flags`; a `flag` event fires on capture.
- Claude-authored PoC generator (`exploit/poc.py`): turns a finding into a PoC
  script artifact (offline template stub when no API key). New `breachload poc`.
- Live dashboard updates: the engine pushes compact state snapshots over the
  WebSocket (`hub.emit_state`), so panels update without polling; polling remains
  a fallback. Late joiners get the latest snapshot on connect.
- Report reproduction steps: each finding lists the successful commands from the
  history that targeted its host.
- Ten more entries in the CVE knowledge base (regreSSHion, Log4Shell, sudo
  Baron Samedit, Ghostcat, PHP-CGI, Heartbleed, Grafana, Webmin, …).
- Web dashboard (`web/`, v0.8): FastAPI + WebSocket server that rides on the
  orchestrator's `on_event` seam. Live event stream, host/service and findings
  panels (polling `/api/state`), Markdown report at `/api/report`, and an
  in-browser confirmation gate — risky actions surface a prompt the operator
  approves/denies, bridged to the engine via an async `EventHub`. New
  `breachload serve` command; requires the `web` extra (`pip install
  'breachload[web]'`).
- Artifact delivery (`exploit/delivery.py`, v0.4): fire a generated artifact at
  a target — `script` (run a PoC against the target) and `upload` (curl the
  artifact) methods. EXPLOIT-classed, so every delivery passes the scope
  validator and confirmation gate. New `breachload deliver` command.
- PDF export (`report/pdf.py`): dependency-free PDF writer renders the report
  with the built-in Courier font. `breachload report --pdf`.
- Reporting (`report/`): renders engagement state to a Markdown report —
  executive summary, host/service inventory, findings ordered by severity,
  credentials, generated artifacts, and an activity timeline. New
  `breachload report` command writes `engagements/<name>/report.md`.
- Exploit-side generation (`exploit/`): `Artifact` state model (generated
  payloads/PoCs as first-class records) and an `msfvenom` payload generator.
  Generation is offline and unrestricted — no target, no scope check — but still
  refuses shell-metacharacter injection. New `breachload payload` CLI command
  writes the artifact under `engagements/<name>/artifacts/` and records it in
  state. (Delivery against a target — the scope- and confirmation-gated step —
  is next.)
- Analysis layer (`analysis/`): version→CVE mapping from a local, offline
  knowledge base (`data/vuln_kb.json`) with a simple version-constraint matcher;
  a cross-service correlator (MS17-010/EternalBlue candidate, cleartext FTP/
  Telnet, anonymous FTP); and an `Analyzer` that folds both into findings,
  deduplicated. Wired into the orchestrator to enrich state after each step.
- Web-recon adapters: `whatweb` (HTTP fingerprinting → service product/techs),
  `ffuf` (content discovery → paths as notes + findings), `nuclei` (templated
  vuln scan → findings with mapped severity and CVE ids).
- `enum4linux-ng` adapter: SMB/NetBIOS enumeration → SMB service, null-session
  and readable-share findings, usernames as credential leads.
- OUTFILE mechanism in the adapter base: tools that emit machine-readable output
  to a file (not stdout) use the `{OUTFILE}` marker; the runner allocates a temp
  path, substitutes it, and reads the result back — safe under scope validation.
- Capability- and state-driven heuristic planner: selects the right tool per
  phase (recon→nmap, enum→whatweb/ffuf/enum4linux-ng, vuln→nuclei) and skips
  work already done.
- Automatic phase transitions: `Orchestrator.run_engagement` walks
  recon → enumeration → vuln; `breachload run` auto-chains by default, with
  `--phase` for a single phase and `--stop` to bound the chain.
- End-to-end orchestrator test proving the full chain populates state (38 tests).
- Exploit-side: msfvenom payload generator + Artifact state model — _planned_
- Web dashboard (FastAPI + WebSocket) for live follow-along and confirmation
  gates, on top of the orchestrator's `on_event` seam — _planned (v0.8)_

### Fixed
- Removed dead CVE knowledge-base entries whose `match` tokens can never appear
  in a service banner (`heartbleed`, `log4j`, `sudo`) or whose version range was
  unrepresentable by the numeric comparator (`<1.0.1g`); corrected the Tomcat and
  Webmin tokens to the real nmap product names. A new test asserts every KB entry
  is reachable, so dead entries can't creep back in.
- CLI output is ASCII-safe and does not pass tool/payload text through Rich
  markup, so payloads containing `[ ] { }` and non-cp1250 characters no longer
  crash the Windows console.
- Payload generation reports a clean error when the generator binary (e.g.
  msfvenom) is not installed, instead of crashing with a raw traceback.
- Engagement `mode` (advisor / semi-auto / full-auto) now actually controls the
  confirmation threshold instead of being a decorative field: advisor confirms
  every action, semi-auto auto-runs only passive/recon, full-auto uses
  `auto_threshold`.
- ffuf now attaches discovered paths to the correct service port (it previously
  assumed port 80, mislabelling services on 8080/8443/etc.).
- The orchestrator isolates tool failures: a crashing/timed-out/unparseable
  adapter no longer aborts the whole engagement — it is logged, recorded, and
  the run continues (and the record stops the planner re-proposing it).
- The Claude planner falls back to the heuristic on any API error (network, rate
  limit, auth) instead of crashing the run.
- `extract_targets` no longer misreads file-path arguments (e.g. a wordlist
  `common.txt`) as hostnames, which had blocked legitimate ffuf commands.
- nmap address parsing used a truthiness test on an XML element (deprecated and
  wrong for empty elements); now an explicit `is not None` check.
- CLI no longer crashes rendering help/output on non-UTF-8 Windows consoles
  (replaced `→`/box-drawing characters with ASCII).

## [0.1.0] - 2026-07-27

Initial scaffold. Deterministic core with a working recon pipeline.

### Added
- Structured engagement state (`core/state.py`): Host, Service, Credential,
  Finding, ActionRecord models with JSON persistence.
- Safety layer (`safety/`): scope allowlist (CIDR/domain/exclude), command
  validator (binary allowlist, shell-metacharacter block, Risk classifier),
  append-only audit log.
- Tool adapter contract (`tools/base.py`) and the reference nmap adapter
  (XML → structured state).
- Orchestrator reasoning loop: plan → validate → run → parse → audit.
- Claude planner (`core/llm.py`) with an offline heuristic fallback so the
  pipeline runs without an API key.
- Engagement config (YAML) with per-engagement scope and autonomy threshold.
- Typer + Rich CLI: `breachload run`, `breachload status`.

[Unreleased]: https://github.com/Noxiidus/breachload/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/Noxiidus/breachload/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/Noxiidus/breachload/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Noxiidus/breachload/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Noxiidus/breachload/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/Noxiidus/breachload/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/Noxiidus/breachload/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/Noxiidus/breachload/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Noxiidus/breachload/compare/v0.3.0...v0.9.0
[0.3.0]: https://github.com/Noxiidus/breachload/releases/tag/v0.3.0
[0.1.0]: https://github.com/Noxiidus/breachload/releases/tag/v0.1.0
