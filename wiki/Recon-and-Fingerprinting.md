# Recon & Fingerprinting

The stage where breachload builds an attack-surface map you can act on. This
is where the tool spends most of its wall-time on a new box, and where it's
strongest.

## What runs, in order

The `run` command autochains RECON → ENUM → VULN. The heuristic planner picks
one action per step from what's known about the state.

### 1. RECON — what's alive, on what ports

- **nmap** service + version scan on every target. Full-port opt-in via
  `scan_all_ports: true` in the YAML (CTF mode enables it automatically).
- **UDP top-ports pass** (`udp_scan: true`) — surfaces SNMP/DNS/TFTP/IKE that
  a TCP-only scan misses.

Every open service becomes a typed `Service` record (`port`, `name`, `product`,
`version`) under a `Host`. Nothing else looks at raw nmap XML — the parsing is
done once, in code, right here.

### 2. ENUM — who each service is

The planner picks tools per service. Web services get **deep fingerprinting**:

- **httpx** — headers, tech, title, status
- **whatweb** — cross-checked signature engine
- **appfinger** — retrieves the app root with a bounded byte-range GET,
  matches against ~30 signatures (FreePBX, GLPI, Nextcloud, NiFi, Zabbix, …),
  writes back a `webapp: <Name> <version>` note
- **ffuf** — directory content discovery with the configured wordlist +
  extensions

Non-web services get their own adapter:

- SMB → **netexec** (banner, host/domain/OS) + **enum4linux-ng**
- LDAP, SNMP, NFS, FTP, redis, SMTP, mysql/postgres/mssql/mongodb, rpc,
  rsync — each with a dedicated adapter that parses output into notes +
  credentials + findings
- **DNS** on port 53 → **AXFR zone-transfer attempt** (folds every A/AAAA
  into the state as a new host)

Web-only hosts also get:

- **vhostfuzz** (20k subdomain wordlist by default) — the *thing* that finds
  the app hidden behind a subdomain, which makes or breaks many boxes
- **`/etc/hosts` opt-in writer** (`hosts --write`) so discovered vhosts
  actually resolve

### 3. VULN — known-CVE mapping

For every fingerprinted HTTP service:

- If the fingerprint already names a CVE (from the KB): **nuclei with `-id`
  on that exact CVE template** — fast, low-noise confirmation.
- Else if we know the stack (nuclei tag map matches): **nuclei with `-tags`
  narrowed to the stack.**
- Else: **safety-net pass** — `nuclei -tags cve -severity high,critical` so
  an unknown app still gets a bounded known-CVE sweep instead of nothing.

Every nuclei match becomes a `confirmed` `Finding` with CVSS, CVE, and the
matched URL.

## Class-level detectors (in ENUM phase and on-demand)

These are the *generalized* pieces — they don't need per-app knowledge:

- `breachload secrets --discover <URL>` — probes `.git/HEAD`, `.env`,
  `wp-config.php.bak`, actuator/env, `/id_rsa`, `.DS_Store` and similar
  high-signal paths.
- `breachload unauthapi <URL>` — probes ~18 unauthenticated management/API
  endpoints (NiFi supportsLogin, Spring actuator, ES `/_cluster/health`, K8s
  API, Docker Engine, Consul, Vault, Jenkins, Swagger/OpenAPI, …) with a
  marker-regex that distinguishes real data from a generic 200.
- `breachload defaultcreds <cfg>` — argv sweep for vendor defaults across
  every detected service + 30+ web-app default logins.

Everything they discover flows into the same `state.json` the rest of the
tool operates on.

## What you see live

Run `breachload run <cfg> --stop vuln` and you get a line-by-line stream:

```
    phase == entering recon ==
      run $ nmap -sV -sC -Pn -oX <tmp> 10.10.10.5
      note nmap: 22/tcp ssh OpenSSH 8.9p1; 80/tcp http nginx 1.18.0
    phase == entering enumeration ==
      run $ httpx -silent -json -title -tech-detect -u http://10.10.10.5:80
      run $ curl -s -L -i -r 0-131072 ... http://10.10.10.5:80/     # appfinger
      note appfinger: WordPress 6.4
      run $ ffuf -w subdomains-top1million-20000.txt -u http://10.10.10.5/ -H 'Host: FUZZ.mybox.htb'
      note vhostfuzz: dev.mybox.htb (200)
```

## What if something's missing

- `breachload doctor` — which external tools you have and don't.
- `breachload doctor --install` — the copy-paste install lines.
- Missing tools = fewer findings, never a crash. breachload skips
  the adapter and moves on.

## Common gotchas

- **VPN MTU on HTB** — a too-high `tun0` MTU makes big HTTP responses stall.
  `breachload doctor --target <IP>` diagnoses it; fix with
  `sudo ip link set tun0 mtu 1300`.
- **Vhost app not showing up** — most likely a subdomain not in `/etc/hosts`.
  `breachload hosts <cfg> --write` fixes it once vhostfuzz found the name.
- **Recon "no output" on a specific service** — the tool is installed but
  the wordlist is missing. `breachload doctor` lists the wordlists it checks.

Next: [Guided Exploitation](Guided-Exploitation) — going from a finding to a shell.
