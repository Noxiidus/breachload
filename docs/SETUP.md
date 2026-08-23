# breachload — Setup & Quickstart

Point-by-point, copy-paste setup on a **fresh Kali/Debian VM**, from cloning the
repo to running the fully-autonomous auto-exploit mode. Hand this to a teammate as-is.

> Authorization: only run breachload against machines you are **authorized** to test
> (your own labs, an engagement with written permission, or a platform like Hack The
> Box that authorizes attacking its machines). Auto-exploit mode is gated on an
> operator key **and** a per-engagement `authorized: true` attestation.

---

## 0. Prerequisites

- Kali Linux (recommended) or Debian/Ubuntu. Python **3.12+**, `git`.
- The repo is **private** — you need access. Either be added as a collaborator on
  `github.com/Noxiidus/breachload`, or clone with a token / SSH key.

```bash
python3 --version        # must be >= 3.12
sudo apt update
sudo apt install -y git python3-venv python3-pip
```

## 1. Clone the repo

```bash
cd ~
git clone https://github.com/Noxiidus/breachload.git
# (private repo: if prompted, use a GitHub Personal Access Token as the password,
#  or:  git clone git@github.com:Noxiidus/breachload.git  with an SSH key)
cd breachload
```

## 2. Install breachload

Use an isolated venv (cleanest — works on Kali's externally-managed Python):

```bash
python3 -m venv ~/bl-venv
~/bl-venv/bin/pip install --upgrade pip
~/bl-venv/bin/pip install -e '.[web]'          # editable install + web dashboard extra

# make the `breachload` command available in this shell:
export PATH="$HOME/bl-venv/bin:$PATH"
# (persist it: echo 'export PATH="$HOME/bl-venv/bin:$PATH"' >> ~/.bashrc)

breachload --help                               # sanity check
```

## 3. Check your tools

```bash
breachload doctor                # what's installed vs missing
breachload doctor --install      # prints the exact install command for each missing tool
```

Kali already ships most of them. Install any missing ones with the commands
`doctor --install` prints (nmap, whatweb, ffuf, nuclei, netexec, certipy, …).

## 4. Learn the tool (optional, for beginners)

```bash
breachload explain               # list glossary terms
breachload explain ssti          # what a term means + what breachload does
breachload payloads              # browse the offline payload library
breachload gtfo find             # GTFOBins lookup
```

## 5. Connect to Hack The Box (for the Connected demo)

Download your **Machines** VPN `.ovpn` from the HTB site, then:

```bash
sudo openvpn --config ~/machines.ovpn --daemon --log ~/vpn.log
sleep 8
ip -br addr show tun0                            # you should see a 10.10.x address
sudo ip link set dev tun0 mtu 1300               # IMPORTANT: avoids large-response stalls
ping -c2 10.129.110.230                          # replace with your spawned box IP
```

> If web fingerprinting comes back empty and full pages "hang", it's almost always
> the MTU — `breachload doctor --target <ip>` will detect and confirm it.

## 6. Create an engagement

Interactive wizard (writes the YAML, includes an authorization checklist):

```bash
breachload init
```

…or write it by hand. For the **autonomous** mode you need the two extra flags:

```yaml
# engagements/connected.yaml
name: connected
targets: ["10.129.110.230", "connected.htb"]   # box IP (+ its vhost once known)
lhost: "10.10.14.5"                             # your tun0 IP (see `ip a`)
lport: 4444
ctf: true
# --- only needed for `auto-exploit` (autonomous) mode: ---
auto_exploit: true
authorized: true                                # you attest you have permission
```

Map the vhost so it resolves (needed for Connected):

```bash
echo '10.129.110.230 connected.htb' | sudo tee -a /etc/hosts
```

## 7. Run — the safe, confirm-gated flow

This never auto-fires exploits; it maps the surface and hands you a plan + report.

```bash
breachload auto engagements/connected.yaml
breachload status  engagements/connected.yaml
breachload report  engagements/connected.yaml --pdf
```

## 8. Set up the operator key (required for auto-exploit mode)

The autonomous mode is gated on an operator allowlist kept **outside** the repo.

```bash
mkdir -p ~/.config/breachload

# 1) generate a random token
python3 -c 'import secrets; print(secrets.token_urlsafe(24))'

# 2) create the operators file (replace <you> and the token):
cat > ~/.config/breachload/operators.json <<'EOF'
{ "operators": [ { "id": "noxi", "token": "PASTE-THE-GENERATED-TOKEN", "note": "owner" } ] }
EOF
chmod 600 ~/.config/breachload/operators.json

# 3) identify yourself in the environment (each shell that runs auto-exploit):
export BREACHLOAD_OPERATOR=noxi
export BREACHLOAD_TOKEN=PASTE-THE-GENERATED-TOKEN
```

To add a **colleague**: generate them their own token, add another `{id, token}`
entry to this file, and give them their token securely (not over chat/git). They
set `BREACHLOAD_OPERATOR` / `BREACHLOAD_TOKEN` to their own values. The gate records
*who* ran each autonomous engagement. (It is an authorization + audit control, not
tamper-proof DRM — the real limits are the scope allowlist and the audit log.)

## 9. Run — the fully-autonomous auto-exploit mode

With the operator key exported and `auto_exploit: true` + `authorized: true` in the
YAML:

```bash
breachload auto-exploit engagements/connected.yaml
```

What it does, unattended: recon → enum → vuln → fires read-only CVE probes → for a
matching KB CVE with a coded module (e.g. **FreePBX CVE-2025-57819**) auto-establishes
a foothold session → runs privilege-escalation enumeration through that session →
fires a curated escalation (full sudo / sudo-NOPASSWD / docker group / SUID shell /
cap_setuid) and reads `/root/root.txt`. Off-scope is always hard-blocked, DESTRUCTIVE
actions still ask a human, and every action is audited to
`engagements/connected/audit.jsonl`.

If you already popped a shell yourself and just want the autonomous privesc, register
the session first:

```bash
breachload session engagements/connected.yaml --webshell 'http://connected.htb/shell.php?cmd=FUZZ' --test
breachload auto-exploit engagements/connected.yaml
```

## 10. After the engagement — cleanup

Auto-foothold modules drop a visible webshell (e.g. `/var/www/html/shell.php`). Remove
it and any artifacts you created:

```bash
curl -s 'http://connected.htb/shell.php?cmd=rm%20-f%20/var/www/html/shell.php'
```

Submit the flags breachload captured (shown in the run + `breachload status`) on the
HTB portal.

---

## Command cheat-sheet

| Goal | Command |
|------|---------|
| Check tools | `breachload doctor` / `doctor --install` |
| Learn a term | `breachload explain <term>` |
| New engagement | `breachload init` |
| Preview (no touch) | `breachload run <cfg> --dry-run` |
| Safe walk + plan + report | `breachload auto <cfg>` |
| MTU probe | `breachload doctor --target <ip>` |
| Add /etc/hosts vhosts | `breachload hosts <cfg> --write` |
| Register a foothold | `breachload session <cfg> --webshell '...FUZZ' \| --ssh user:pass@host` |
| **Autonomous** run | `breachload auto-exploit <cfg>` |
| Crack a hash | `breachload crack <cfg> --hash <h> --run` |
| Parse loot / ADCS / BloodHound | `breachload loot\|adcs\|bloodhound <cfg> --scan <file>` |
| Windows privesc playbook | `breachload winprivesc <cfg>` |
| Live dashboard | `breachload serve <cfg>` |
