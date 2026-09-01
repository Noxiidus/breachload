# Live Dogfood

The one gap between "unit-tested" and "battle-tested" is a live run against
real retired HTB boxes. Everything else is speculation. This page is the
reproducible workflow that turns dogfood into MEASURED coverage.

Full checklist lives in [docs/DOGFOOD.md](../docs/DOGFOOD.md); this page is
the wiki intro + how to feed results back as regression tests.

## Why dogfood

- Unit tests prove `parse_x(fixture)` works. They don't prove the tool
  finds the lead the writeup uses.
- The Docker `tests/live/` harness proves the auto-foothold modules land
  against a controlled vulnerable image. It doesn't cover breadth.
- Held-out coverage against ~10 retired boxes proves the tool
  generalises — the actual claim we're trying to defend.

## The per-box workflow (10-30 min per box)

Prerequisites: WSL Kali, breachload in `~/bl-venv` (editable), HTB VPN up,
tun0 MTU set to 1300, sudo passwordless.

```bash
IP=10.129.<box-ip>
NAME=<boxname>

# Config
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

# Recon -> vuln
~/bl-venv/bin/python -m breachload.cli run engagements/${NAME}.yaml --stop vuln

# What did it find WITHOUT hints
~/bl-venv/bin/python -m breachload.cli status engagements/${NAME}.yaml
~/bl-venv/bin/python -m breachload.cli suggest engagements/${NAME}.yaml

# Class-detector sweep for every HTTP service in state
python - <<'PYEOF'
import json
st = json.load(open("engagements/${NAME}/state.json"))
for h in st["hosts"].values():
    for s in h["services"].values():
        if "http" in (s.get("name") or "").lower():
            scheme = "https" if s["port"] in (443, 8443) else "http"
            print(f"{scheme}://{h['address']}:{s['port']}/")
PYEOF
# then loop those URLs through:
breachload secrets --discover <url>
breachload unauthapi <url>

# Default-cred sweep across every service in state
breachload defaultcreds engagements/${NAME}.yaml
```

## Scoring

After each box, add one line to `docs/dogfood-scores.csv`:

```
name,difficulty,recon_coverage,guided_fit,autonomous_hit,notes
mybox,easy,1,1,0,"NiFi lead surfaced from appfinger; foothold manual; incron privesc not auto"
```

- **recon_coverage** (0/1) — did the recon phase surface the primary lead
  the writeup uses?
- **guided_fit** (0/1) — did any class detector name the correct
  escalation (or a viable equivalent)?
- **autonomous_hit** (0/1) — in auto-exploit mode, did it actually land
  the foothold + privesc? (Most box classes are not auto-fireable and 0
  is fine here.)

Aim for **2/3 on Easy/Medium** as the "battle-tested" bar per class.

## Feed results back as regression tests

After a dogfood run, drop the resulting `state.json` under
`tests/held_out/states/<box>.json`. Add an entry to `EXPECTATIONS` in
`tests/held_out/test_held_out_coverage.py`:

```python
BoxExpectation("mybox", "medium", "webapp-cve-lead",
               ["subdomain", "nifi", "cve-2023-34468"]),
```

Then:

```bash
pytest -m held_out -v
```

If any box regresses, we know instantly. If overall coverage % drops after
a release, that's a release blocker.

## The rule

A gap that shows up on **3+ boxes** gets escalated into the technique-
coverage backlog as a **class fix**, not a per-box patch. The point of the
technique-map is that per-box patches are the anti-pattern; class detectors
are the answer.

## Suggested first-week rotation

Rotate through classes so we cover the whole map:

- **Linux, web-cve foothold** — Cronos, Networked, Bounty Hunter, Cap
- **Windows / AD** — Forest, Sauna, Active, Support
- **Config / secret disclosure** — Popcorn, Nibbles, Traceback
- **Real-CVE modern** — Return, Photobomb

~8-12 boxes is enough for a first coverage signal.
