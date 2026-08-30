# Technique coverage & generalization

The wrong way to grow breachload is one box at a time: patching in a NiFi module
after seeing NiFi only helps NiFi boxes. That is overfitting to a writeup. The right
way is to build to the **technique CLASS**, so an unseen box with **no writeup and no
known path** is still handled when it fits a pattern breachload covers.

This document is the aggregation: the recurring initial-access / privilege-escalation
/ lateral classes (from HTB corpora + HackTricks / PayloadsAllTheThings / GTFOBins /
LOLBAS methodology), each with a rough **frequency** band, whether it **generalizes**,
and breachload's **current coverage**. Build order is driven by *frequency x
generalizability x gap*, not by the last box we happened to see.

Legend — Coverage: ✔ solid · ~ partial · ✗ missing. Freq: how often the class is the
answer on a random box (High/Med/Low). Gen: does covering the class generalize across
boxes?

## Principle: breadth from generalized engines, depth from a small hand-KB

The tools that already generalize should carry the breadth, and we lean on them harder
instead of hand-coding per app:

- **nuclei** (9000+ community templates) = the generalized *app -> known-CVE* engine.
  Our 35-entry `webapp_kb` is not a replacement — it is the **depth** layer (full
  exploit recipe) for the top-frequency apps only. Rule: nuclei for breadth, hand-KB
  for the ~30 apps that recur.
- **linpeas / winPEAS-class enumeration + a technique matcher** = the generalized
  *Linux/Windows privesc* engine. This is the SAME on every box and where breachload is
  already strongest.
- **BloodHound / roasting / ADCS** = the generalized AD engine.
- **default-credential sweeps** across services = generalized initial access.

Everything else is a curated pattern library keyed to a class, never to a box.

## Initial access classes

| Class | Freq | Gen | breachload today | Generalization move |
|-------|------|-----|------------------|---------------------|
| Known-app version -> public CVE/exploit | High | ✔ | ~ nuclei tags + 35 KB entries | Run nuclei comprehensively + parse ALL matches; KB only for depth |
| Default / weak credentials (web + services) | High | ✔ | ~ per-service adapters (mysql blank root, etc.) | A generalized **cred-sweep** across every detected service + common app defaults |
| Exposed admin panel / API with no auth | High | ✔ | ~ appfinger + webcve | A generalized **"unauthenticated admin/API" detector** (probe for `/api`, `/admin`, actuator, management endpoints returning data) |
| SQL injection (login/param) | High | ~ | ~ webattacks first-probe | Deeper automated SQLi probing (sqlmap orchestration, confirm-gated) |
| SSTI / template injection | Med | ~ | ~ webattacks `{{7*7}}` | Per-engine payload ladder + confirm |
| File upload -> webshell | Med | ~ | ✗ | A generalized upload-fuzzer (ext/content-type bypass matrix) |
| LFI / path traversal -> log poison / source disclosure | Med | ~ | ~ webattacks probe | LFI-to-RCE ladder (wrappers, log poison, session) |
| Secret disclosure (.git, .env, backups, config) | High | ✔ | ✗ | A generalized **content-discovery + secret-scan** pass (git-dumper, `.env`, `.bak`, `id_rsa`, config files) — very high ROI, fully general |
| SSRF -> cloud IMDS / internal | Med | ~ | ~ webattacks + loot IMDS parse | Wire SSRF probe -> IMDS creds -> reuse |
| Deserialization (Java/PHP/.NET) | Med | ✗ | ✗ | ysoserial/phpggc payload generation keyed to detected stack |
| Credential reuse from a prior loot | High | ✔ | ✔ suggest lateral/spray | (solid) |
| App config secret -> another service (NiFi-class) | Med | ✔ | ✗ (was hand-coded for NiFi) | Generalize to **"readable app config/state -> extract creds/keys -> reuse"**: a library of config locations + secret formats, not a per-app module |

## Linux privilege escalation classes

| Class | Freq | Gen | breachload today | Generalization move |
|-------|------|-----|------------------|---------------------|
| sudo rights (NOPASSWD / GTFOBins) | High | ✔ | ✔ privesc_auto + gtfobins | (solid) |
| SUID/SGID GTFOBins | High | ✔ | ✔ | (solid) |
| Capabilities (cap_setuid, ...) | Med | ✔ | ✔ | (solid) |
| Cron / timer abuse (writable script/PATH) | High | ✔ | ~ | Generalized writable-cron + PATH-hijack detector from enum |
| Writable service/config sourced by root (NiFi/dahdi-class) | Med | ✔ | ✗ | **Generalized "root reads a file I can write" detector**: cross writable files x files referenced by root units/cron/init |
| Kernel exploit (DirtyPipe/PwnKit/...) | Med | ✔ | ✔ kernelexploits | Keep the version->exploit map current |
| Group membership (docker/lxd/disk/adm) | Med | ✔ | ✔ postexploit.parse_groups | (solid) |
| Password reuse / creds in files/history | High | ✔ | ~ loot | Generalized secret-scan of home/config/history/db |
| NFS no_root_squash / weak mounts | Low | ✔ | ~ nfs adapter | Wire to a privesc suggestion |
| Path/wildcard injection (tar/rsync/etc.) | Low | ✔ | ~ gtfobins | (ok) |

## Windows privilege escalation classes

| Class | Freq | Gen | breachload today | Generalization move |
|-------|------|-----|------------------|---------------------|
| SeImpersonate -> Potato | High | ✔ | ✔ winprivesc_auto | (solid) |
| AlwaysInstallElevated | Med | ✔ | ✔ | (solid) |
| Unquoted service path / weak service ACL | Med | ✔ | ~ winprivesc | Add writable-service-binary + service-ACL detector |
| Autologon / stored creds (cmdkey, registry) | Med | ✔ | ✔ | (solid) |
| Scheduled task abuse | Med | ✔ | ~ | Parse schtasks for writable task binaries |
| DLL hijack / PATH | Low | ~ | ✗ | (lower priority) |
| GPP / SYSVOL cpassword | Med | ✔ | ✗ | Generalized SYSVOL cpassword sweep |

## Lateral / AD classes

| Class | Freq | Gen | breachload today | Move |
|-------|------|-----|------------------|------|
| Kerberoast / AS-REP | High | ✔ | ✔ kerberos + loop | (solid) |
| ADCS ESC1-16 | High | ✔ | ✔ adcs + adchain | (solid) |
| ACL abuse (GenericAll/Write, RBCD) | High | ✔ | ✔ adchain | (solid) |
| DCSync | Med | ✔ | ✔ adchain | (solid) |
| Pass-the-hash / cred reuse / spray | High | ✔ | ✔ suggest | (solid) |
| Delegation (unconstrained/constrained) | Med | ✔ | ~ adchain | Constrained-deleg step |

## Frequency-ranked generalization backlog (build to the CLASS)

The highest *frequency x generalizability x gap* items — these help on **many unseen
boxes**, not one:

1. **Secret-scan + content-discovery pass** (High/general/missing): git-dumper, `.env`,
   `.bak`/`~`/`.old`, `id_rsa`, config files, JS-embedded secrets, `/backup`. This is
   the single most general initial-access win and breachload barely does it.
2. **Generalized "root reads a file I can write" privesc detector** (the real,
   *general* lesson from NiFi/dahdi): cross the set of writable files with files
   referenced by root cron/systemd/init/sourced scripts. Covers a whole class of
   custom-service boxes with no writeup.
3. **App-config secret extraction library** (generalizes the NiFi decrypt): a table of
   *where apps store secrets* + *how they encode them* (plain, base64, app-specific KDF)
   — keyed to the detected app class, not a per-app module.
4. **Comprehensive nuclei orchestration + full parse** (High/general/partial): make
   nuclei the breadth engine; ensure every match becomes a finding with severity.
5. **Generalized unauthenticated-admin/API detector** (High/general/partial): probe
   management endpoints (actuator, `/api`, `/admin`, console) that return data without
   auth — the NiFi `supportsLogin:false` pattern, generalized.
6. **Default-credential sweep** across all detected services + common app logins
   (High/general/partial).
7. **Writable-cron + PATH-hijack + writable-service-binary** detectors from enum output
   (High/general/partial).

## Coverage measurement (prove it generalizes)

Anecdote ("it worked on Helix") is not evidence of generalization. The eval:

1. **Held-out set**: pick N retired boxes NOT consulted while building.
2. For each, run breachload recon->vuln + the privesc enum on a provided shell.
3. Score: did it **surface the correct next lead** (initial access) and the **correct
   privesc class**? Coverage % = boxes where the right class was surfaced without any
   per-box tuning.
4. Track coverage per release. A change only counts if it moves held-out coverage, not
   if it fixes the one box we were looking at.

This file is the map. Every future capability should name the **class** it covers and
the **held-out coverage** it moves — not the box that inspired it.
