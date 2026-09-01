# State + Findings

Everything breachload knows about your engagement is a typed record. Nothing
looks at raw tool stdout except the parsers — the rest of the tool reasons
over this structured state. This page is the mental model.

## Where it lives

```
engagements/<name>/state.json
```

One JSON file per engagement. Serialised through pydantic, atomically saved
(temp + `replace`) so a crash / Ctrl-C mid-write never truncates it.

## The core types

### `Host`
- `address` (IP)
- `hostnames`, `tags` (e.g. `dc`, `domain:corp.local`, `dns-name: mail.x.htb`)
- `os_guess`
- `services` — dict keyed by `port/proto`

### `Service`
- `port`, `protocol`, `name`, `product`, `version`, `state`, `banner`
- `notes` — list of free-form strings the parsers append
  (e.g. `webapp: Apache NiFi 1.21.0`)

### `Credential`
- `service_key` (host:port/proto)
- `username`, `secret`
- `kind` — `password | hash | key | token | ticket`
- `source` — where it came from ("SSRF/IMDS (AWS)", "GPP cpassword", "crack",
  "user-add")
- `validated` — True when we've actually authenticated with it

### `Finding`
- `title` — short and searchable ("Kerberoastable account: svc_sql")
- `severity` — `info | low | medium | high | critical`
- `host`, `service_key` — anchoring
- `description`, `evidence`, `remediation`
- `cve` — list of CVE ids
- `exploit` — a ready, review-then-run command
- `cvss` — optional float (from KB / nuclei)
- **`validation`** — `suspected` (inferred) vs `confirmed` (proven)
- **`proof`** — the concrete evidence of exploitation

### `ActionRecord`
Every command breachload ever proposed, with its exit code, whether it was
approved, phase, tool, and rationale. This drives the report's Activity
timeline + Reproduce steps + the audit chain.

### `EngagementState`
Container for the above, plus `phase`, `flags` (captured CTF flags), and
`history`.

## How data flows in

```
adapter builds argv -> validator checks scope + shell metachars ->
runner executes -> ToolResult (stdout/exit) -> adapter.parse(result, state)
    -> notes/services/hosts/findings appended -> state.save()
```

Then downstream (analyzer, correlator, class detectors) run over the state
and add more findings. Never raw stdout — always structured.

## Reading it

```bash
breachload status <cfg>              # human summary
python -m json.tool engagements/<cfg>/state.json | less   # raw
```

For scripting:

```python
from breachload.core.state import EngagementState
st = EngagementState.model_validate_json(open("state.json").read())
for h in st.hosts.values():
    for s in h.services.values():
        print(h.address, s.port, s.name, s.notes)
```

## Why this matters

- The **LLM planner only sees the state summary**, never raw output. It
  can't hallucinate a service that isn't there.
- The **report** is a pure function of state; regenerate anytime.
- The **MCP server** accepts serialized state and returns tool calls —
  agents drive breachload without touching your target.
- **Held-out coverage** measurement (`analysis/coverage.py`) checks that
  expected tokens appear anywhere in the state after a run.

See [Suspected vs Confirmed](Suspected-vs-Confirmed) for the proof model
that keeps reports honest.
