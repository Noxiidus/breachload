# Suspected vs Confirmed

Every `Finding` in breachload carries a `validation` field:

- **`suspected`** — inferred from a fingerprint, version, or heuristic. It
  may be a real vuln, or a version-guess we haven't verified. Default state
  for anything the parsers infer.
- **`confirmed`** — we actually **proved** it. A probe matched a marker
  regex, a session opened, a hash was recovered, a flag was read, a secret
  matched a strict regex.

Confirmed findings also carry a **`proof`** string — the concrete evidence.

## Why this split matters

Reports without a proof model over-report: everything looks equally
important, the reader learns to distrust the tool. With this split you can
say honestly: "3 confirmed critical, 12 suspected — here is the concrete
evidence for each confirmed one."

The HTML/Markdown report shows:

```
### [CRITICAL] Apache NiFi unauthenticated API -> RCE (CVE-2023-34468)

**Status:** [CONFIRMED]
**CVSS:** 9.8
**Proof:** nuclei template CVE-2023-34468 matched
```

vs.

```
### [HIGH] Old nginx (potential CVE)

**Status:** [suspected]
**CVSS:** 7.5
```

## Where confirmed comes from — by class

| Class | How it becomes confirmed |
|-------|--------------------------|
| Nuclei match | template hit → the matched URL is the proof |
| Auto-foothold module | webshell answered → session opened |
| Autonomous privesc | `/root/root.txt` read → the flag is the proof |
| Windows autonomous SYSTEM | `C:\Users\Administrator\Desktop\root.txt` read |
| Kerberoast/AS-REP hash | actually pulled the `$krb5*$` blob off the wire |
| GPP cpassword decrypt | decoded to a printable string |
| Sensitive path (`.git`, `.env`, actuator) | HTTP 200 + expected marker regex |
| Unauth admin/API | marker regex on the response body |
| Secret scan | regex hit with a non-placeholder value |
| ADCS ESC1 loop | `certipy req` returned `.pfx` |

## Suspected is not "wrong"

A suspected finding is still worth reviewing — it means breachload has
reason to believe. It just hasn't seen the proof yet. Turning a `suspected`
into a `confirmed` is usually one manual `curl` away.

## In the report summary

```
- Findings: **17** (3 critical, 4 high, 5 medium, 5 low)
- Confirmed (proven): **6** · suspected: **11**
```

## Programmatically

```python
confirmed = [f for f in state.findings if f.validation == "confirmed"]
```

## In the dashboard

The web dashboard has a **"show: confirmed only"** filter, and a
`(N confirmed / M total)` badge next to the Findings header. So you can
focus on proven issues during triage.
