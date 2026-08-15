# breachload — HTB / CTF coverage map

*What the tool covers today, what's missing, and what to build next so a single
`breachload auto` walks a typical HTB/CTF box as far as an automated copilot
honestly can. Grounded in live dogfooding (Paperwork, Snapped — 2026-08).*

breachload's contract stays fixed: **deterministic core, LLM only decides; the
safety layer governs where actions land and when a human is needed.** Everything
below respects that — nothing here proposes auto-firing destructive exploits
without a gate.

Legend: ✅ solid · 🟡 partial · ❌ missing · 🔴 high priority

---

## 0. Cross-cutting robustness (bit us live this session)

| Item | State | Note |
|------|-------|------|
| VPN MTU / large-response stalls | ❌ 🔴 | tun0 MTU 1500 stalled every response >~1 MTU; looked like "app hangs". `doctor` should probe path MTU (send a big-ish GET to the target and time it) and warn/suggest `ip link set tun0 mtu 1300`. |
| `/etc/hosts` management | 🟡 | vhost/redirect discovery is inert until the name resolves. Surface the exact line (done as a finding) **and** offer an opt-in `--write-hosts` that appends discovered vhosts (privileged, confirm-gated). |
| Hanging / streaming endpoints | 🟡 | whatweb now bounded + noted. Add: on a hung full GET, retry with `Range: bytes=0-4096` (served instantly even when full GET stalls — proven on Snapped) and fingerprint that. |
| Full-port + UDP recon | ❌ 🔴 | recon is default-1000 TCP `-sV` only. Add `-p-` sweep (toggle) and a top-UDP pass (SNMP/DNS/TFTP/IKE hide there). |
| Distro-backport CVE false positives | 🟡 | OpenSSH 9.6p1 flagged regreSSHion, but `3ubuntu13.15` is backport-patched. Correlator should down-rank a CVE when the banner carries a distro patch suffix. |

---

## 1. Recon

✅ nmap `-sV` → structured host/service/version, OS guess.
❌ 🔴 full-port (`-p-`) and UDP passes · ❌ `nmap -sC`/vuln NSE scripts · ❌ auto re-scan of newly discovered hosts (subnet from a foothold).

## 2. Web enumeration

✅ whatweb (fingerprint + redirect→vhost pivot) · ✅ ffuf content discovery (fixed) · ✅ **vhostfuzz** (found `admin.snapped.htb` live) · 🟡 httpx (name-collision aware).
- ❌ 🔴 **Recursive / extension ffuf** (`-recursion`, `-e php,txt,bak,zip`) — one-level common.txt misses most real trees.
- ❌ 🔴 **Parameter / API fuzzing** — `arjun`-style param discovery, `/api/*` + GraphQL introspection, Swagger/OpenAPI parsing.
- ❌ **Auth-aware scanning** — once creds/a cookie are known, re-crawl behind login.
- ❌ **Known-app version→CVE for web apps** — Nginx UI 2.3.2 was fingerprinted (`/version.json`) but never mapped to CVE-2026-27944. A web-app→CVE KB (WordPress/Joomla/Gitea/Jenkins/Grafana/Nginx UI/…) is the single highest-value add.
- ❌ nikto / nuclei-with-tags per detected stack · ❌ LFI/SQLi/SSTI/XXE probes (even light, confirm-gated) · ❌ virtual-host + `/robots.txt` + `sitemap.xml` + JS-endpoint (`linkfinder`) harvesting.

## 3. Service enumeration (non-web)

✅ SMB via netexec + enum4linux-ng.
- ❌ 🔴 **FTP** (anon login, version→CVE), **SNMP** (`snmpwalk` public), **NFS** (`showmount`), **RPC** (`rpcinfo`), **LDAP** (anon binds), **rsync**, **redis/memcached** (unauth), **MySQL/MSSQL/PostgreSQL/MongoDB** (default/blank creds), **SMTP** (VRFY/user enum), **IMAP/POP3**, **Kerberos** (already partial via AD).
- Each is a small adapter in the existing pattern; this is the widest coverage gap for "service" boxes.

## 4. Vulnerability analysis

✅ nuclei (JSONL → findings) · ✅ version→CVE correlator + searchsploit.
- ❌ 🔴 **KB coverage** — the two CVEs that solved Snapped (nginx-ui backup disclosure, snapd LPE) weren't in the KB. Ship a curated, regularly-imported KB of HTB-relevant CVEs; `kb-import` exists — feed it.
- ❌ nuclei auto-tagging from detected tech · ❌ correlate a service version to a *specific* public PoC/exploit path, not just a CVE id.

## 5. Exploitation

✅ offline payload library + msfvenom gen + confirm-gated delivery · ✅ GTFOBins lookup · ✅ rule-based suggestions with LHOST/LPORT filled.
- ❌ **Guided known-CVE exploitation** — for a KB CVE with a public PoC, generate a ready-to-run local script (confirm-gated), e.g. the nginx-ui backup-decrypt or a snapd-LPE builder. Not auto-fire; a filled-in, reviewed command.
- ❌ **Reverse-shell catcher / handler** — spin a listener, host payloads over HTTP, track callbacks.

## 6. Credential attacks

🟡 hydra present (brute) but not wired into an automatic flow.
- ❌ 🔴 **Hash cracking integration** — Snapped's foothold needed cracking a bcrypt from a leaked DB. A `crack` command (hashcat/john + rockyou, mode auto-detect) that feeds cracked creds back into state would close a very common loop.
- ❌ default/weak-cred spraying against discovered services (SSH/FTP/SMB/web-login) · ❌ credential reuse across services once one is found.

## 7. Post-exploitation & privilege escalation (Linux)

✅ `loot` parses linpeas/creds · ✅ GTFOBins.
- ❌ 🔴 **Automated privesc enumeration** — upload+run linpeas/pspy over the foothold (SSH/shell), then parse: SUID/SGID, sudo `-l`, capabilities, cron, writable paths, kernel version → **kernel/exploit suggestion** (pwnkit, dirtypipe, **snapd/snap-confine**, overlayfs, nf_tables…).
- ❌ container/orchestration escapes (docker.sock, lxd/lxc, privileged containers, k8s) · ❌ SSH-key / `authorized_keys` / `.bash_history` / config-secret harvesting.
- Note: breachload is a **copilot** — it should *drive enumeration and name the exploit*, then hand a reviewed command to the operator (as it does for delivery). Snapped's snapd race is a good example: breachload should have identified snapd 2.63.1 + SUID snap-confine and named CVE-2026-3888.

## 8. Pivoting / lateral movement

✅ tunnel suggestions (chisel/ligolo/ssh/proxychains), now machine-count-correct.
- ❌ auto-generate the ready chisel/ligolo command with the real LHOST + discovered internal subnet · ❌ re-run recon through the tunnel.

## 9. Windows / Active Directory

✅ DC detection, AD attack chains (nxc/BloodHound/certipy/kerberos/spray) with looted creds auto-filled.
- ❌ Windows **local** privesc enumeration (winPEAS, `PrivescCheck`, potato family, unquoted-service-path, AlwaysInstallElevated) — the Linux/Windows privesc gap mirrors §7.

## 10. Flag & reporting

✅ flag capture (bare-hex aware) · ✅ Markdown/PDF report + reproduce steps (now `{OUTFILE}`-clean) · ✅ live web dashboard.
- 🟡 report could include a per-finding "exploit path" section when a KB CVE matches.

---

## Priorities (highest leverage first)

1. **Web-app version→CVE KB + known-CVE guided exploitation** (§2/§4/§5) — turns fingerprints into footholds; this is what actually solves web boxes.
2. **Automated Linux privesc enum + kernel/exploit suggestion** (§7) — the other half of every box.
3. **Non-web service adapters** (§3) — FTP/SNMP/NFS/DB/SMTP/redis — broad, cheap, high hit-rate.
4. **Hash-cracking + credential reuse loop** (§6) — recurring foothold mechanic.
5. **Recon depth**: `-p-`, UDP, recursive/extension web fuzzing (§1/§2).
6. **Network robustness**: MTU probe, `/etc/hosts` opt-in write, Range-retry on hung GET (§0).

## What breachload should NOT try to be

An autonomous exploit-firing bot. The wins this session came from breachload
**mapping the surface** (vhostfuzz → admin panel → version) and a human taking the
named CVE from there. Keep exploitation **guided and confirm-gated**: identify,
name the CVE, generate a reviewed command — never auto-pop a shell unprompted.
