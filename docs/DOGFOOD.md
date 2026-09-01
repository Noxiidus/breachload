# Live-box dogfood harness

The one gap between "unit-tested" and "battle-tested" is a live run against real
retired HTB boxes. Everything else is speculation. This doc + the helper script
turn a dogfood session into a reproducible workflow that MEASURES what worked
instead of anecdote.

## The measured claim

Per box, we score three things:

1. **Recon coverage** - did `breachload run` surface the primary lead the writeup
   uses (a specific service/CVE/vhost) WITHOUT us handing it hints?
2. **Guided-exploit fit** - did any KB entry / class detector name the actual
   escalation the writeup uses (or a viable equivalent)?
3. **Autonomous-fire hit** - in `auto-exploit` mode, did it actually land the
   foothold + privesc? (Optional; most box classes are not auto-fireable and
   this is expected.)

A score of 2/3 or higher on Easy/Medium is the "battle-tested" bar for that
class of box. Track per-box + running average per release.

## Preparation (once)

```bash
# WSL Kali, breachload editable in ~/bl-venv (see project memory: matches existing setup)
# HTB VPN active: ~/htb/<pack>.ovpn -> tun0 up, MTU 1300
sudo openvpn --config ~/htb/machines_eu.ovpn --daemon --log /tmp/vpn.log
sudo ip link set dev tun0 mtu 1300
```

## Per-box workflow (10-30 min per box)

```bash
IP=10.129.<box-ip>
NAME=<boxname>

# 1. Config
cat > engagements/${NAME}.yaml <<YAML
name: ${NAME}
mode: full-auto
ctf: true
targets:
  - ${IP}
  - ${NAME}.htb
  - "*.${NAME}.htb"
auto_threshold: active
lhost: 10.10.14.<your-tun-ip>
notes: HTB "${NAME}" dogfood run.
YAML

# 2. Recon -> vuln (deterministic, wait it out)
~/bl-venv/bin/python -m breachload.cli run engagements/${NAME}.yaml --stop vuln

# 3. What did it find without hints?
~/bl-venv/bin/python -m breachload.cli status engagements/${NAME}.yaml
~/bl-venv/bin/python -m breachload.cli suggest engagements/${NAME}.yaml

# 4. Web-app-focused generalized detectors on each fingerprinted HTTP service
for url in $(python -c 'import json,sys,glob
st=json.load(open("engagements/'${NAME}'/state.json"))
for h in st["hosts"].values():
    for s in h["services"].values():
        if "http" in (s.get("name") or "").lower():
            scheme="https" if s["port"] in (443,8443) else "http"
            print(f"{scheme}://{h[\"address\"]}:{s[\"port\"]}/")'); do
  ~/bl-venv/bin/python -m breachload.cli secrets --discover "$url"
  ~/bl-venv/bin/python -m breachload.cli unauthapi "$url"
done

# 5. Cred sweep against every service in state
~/bl-venv/bin/python -m breachload.cli defaultcreds engagements/${NAME}.yaml

# 6. Once you have a shell (however it landed), record a session and let the
#    autonomous privesc + class detectors chew on it:
~/bl-venv/bin/python -m breachload.cli session engagements/${NAME}.yaml \
    --webshell 'http://<host>/shell.php?cmd=FUZZ'
BREACHLOAD_OPERATOR=noxi BREACHLOAD_TOKEN=<token> \
    ~/bl-venv/bin/python -m breachload.cli auto-exploit engagements/${NAME}.yaml --yes

# 7. Score + notes
echo "recon_coverage,guided_fit,autonomous_hit,notes" >> docs/dogfood-scores.csv
# then append: <name>,<0-1>,<0-1>,<0-1>,<one line>
```

## Suggested box order (retired only)

Rotate through classes so we cover the whole map:

- **Linux, web-cve foothold**: Cronos, TartarSauce, Networked, Bounty Hunter,
  Cap - test that appfinger + webcve KB name the lead
- **Windows / AD**: Forest, Sauna, Active, Support - test Kerberoast + ADCS
  auto-loop + adchain
- **Config / secret disclosure**: Popcorn, Nibbles, Traceback - test secretscan
  + content-discovery
- **ICS / unusual**: Poison, Sense - class detectors, expected partial
- **Real-CVE modern**: Return (RPC printer), Photobomb (unsanitized shell) -
  guided exploitation

Aim for ~8-12 boxes over the dogfood week; that's enough for a signal.

## Recording the outcome

After every box, ONE line into `docs/dogfood-scores.csv`. Weekly aggregate into
`docs/DOGFOOD-RESULTS.md` (per-class averages + top gaps). A gap that shows up
on 3+ boxes gets escalated into the technique-coverage backlog as a class fix -
NEVER a per-box patch.
