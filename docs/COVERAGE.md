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
| VPN MTU / large-response stalls | ✅ | `doctor --target <ip>` probes path MTU (tiny ranged GET vs full GET) and prints the `ip link set tun0 mtu 1300` fix when the stall pattern shows. |
| `/etc/hosts` management | ✅ | The redirect/vhost finding surfaces the line, **and** `hosts --write` appends discovered vhosts to /etc/hosts (privileged, confirm-gated). |
| Hanging / streaming endpoints | 🟡 | whatweb bounded + noted; the MTU probe addresses the common root cause. Range-retry (`Range: bytes=0-4096`) on a hung full GET still todo. |
| Full-port + UDP recon | ✅ | `full_ports` (`-p-`) shipped; `udp_scan` adds a top-ports `nmap -sU` pass (SNMP/DNS/TFTP/IKE). |
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

✅ SMB via netexec + enum4linux-ng. ✅ FTP (anon), SNMP (public), NFS (showmount), Redis (unauth),
SMTP (VRFY), MySQL/PostgreSQL/MSSQL (blank/default creds) — all shipped as adapters.
- ⏳ still todo: **RPC** (`rpcinfo`), **LDAP** (anon binds), **rsync**, **memcached**, **MongoDB**,
  **IMAP/POP3**. Each is a small adapter in the existing pattern.

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

Progress: ✅ shipped · 🚧 partial · ⏳ todo

1. ✅ **Web-app version→CVE KB + known-CVE guided exploitation** (§2/§4/§5) — `analysis/webcve.py`
   + `data/webapp_kb.json` map a fingerprinted web app (from service notes) to a CVE and attach a
   ready, confirm-gated exploit command; whatweb now emits `webapp: <Name> <version>` notes to feed it.
2. ✅ **Automated Linux privesc enum + kernel/exploit suggestion** (§7) — kernel suggester
   (`kernelexploits.py`) + the `privesc` playbook (`privesc_enum.py`: transfer/run linpeas/pspy with the
   real LHOST, then loot-back) + group-membership privesc (docker/lxd/disk) in `loot`.
3. ✅ **Non-web service adapters** (§3) — snmp/nfs/ftp/redis **and** smtp/mysql/postgres/mssql shipped.
4. ✅ **Hash-cracking + credential reuse loop** (§6) — `analysis/hashcrack.py` + `crack` command
   (identify → rockyou hashcat/john commands → optional live crack → store → reuse via lateral suggestions).
5. ✅ **Recon depth** (§1/§2) — full-port `-p-`, ffuf `web_extensions`, **UDP top-ports pass** (`udp_scan`)
   and **recursive ffuf** (`ffuf_recursion`/`recursion_depth`), all threaded from the engagement config.
6. 🚧 **Network robustness** — **MTU probe** (`doctor --target`) and **`/etc/hosts` opt-in write**
   (`hosts --write`) shipped; Range-retry on a hung full GET still todo (MTU probe addresses the root cause).

Also shipped: **web attack-surface probes** (`webattacks.py` — SSTI/SQLi/LFI/upload/cmdi/SSRF+IMDS/XXE/JWT
first-probe payloads per HTTP host, §2). Still todo: nuclei auto-tagging from detected tech, auth-aware
re-crawl behind login, and the **dangling ADCS template** detector idea (diff CA `-list-templates` vs
existing template objects) from the DanglingTree solve.

## What breachload should NOT try to be

By **default**, an autonomous exploit-firing bot. The wins came from breachload
**mapping the surface** (vhostfuzz → admin panel → version) and a human taking the
named CVE from there. The default posture keeps exploitation **guided and
confirm-gated**: identify, name the CVE, generate a reviewed command — never
auto-pop a shell unprompted.

**Exception — the opt-in `auto-exploit` mode** (`docs/AUTO-EXPLOIT.md`): an
authorized, audited, per-engagement mode that removes the confirmation prompt up to
EXPLOIT and auto-walks through exploitation/post-exploitation. It exists for
operators with written authorization for the whole scope, behind an operator gate.
Even there the non-negotiables hold: **scope stays absolute** (off-scope hard-
blocked), **DESTRUCTIVE still asks a human**, everything is audited, and only
validated argv commands run (no shell) — so autonomous firing is bounded to what is
expressible safely. It is a conscious, gated exception, not the default.
