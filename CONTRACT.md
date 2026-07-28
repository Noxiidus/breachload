# Stable contracts

These interfaces are the load-bearing surface third parties build on and the
safety model everything else depends on. From v1.0 they follow semantic
versioning: no breaking change to anything below without a major-version bump.
Everything not listed here is internal and may change at any time.

## Tool adapter API (`breachload.tools.base`)

A tool is a `ToolAdapter` subclass. Register it under the `breachload.tools`
entry-point group to have it discovered automatically (see the walkthrough).

```python
from breachload.tools.base import ToolAdapter, ToolResult
from breachload.safety.validator import Risk

class MyScannerAdapter(ToolAdapter):
    name = "myscanner"          # unique key in the registry
    binary = "myscanner"        # the executable; added to the allowlist
    risk = Risk.ACTIVE          # how the validator classes this tool
    capabilities = ["http"]     # tags the planner matches per phase

    def build_command(self, target: str, **kwargs) -> list[str]:
        # Return an argv list — NEVER a shell string. It must be scope-checkable:
        # any host/IP/URL it touches has to appear as an argument.
        return [self.binary, "--json", target]

    def parse(self, result: ToolResult, state) -> list[str]:
        # Fold result.stdout / result.output_file into `state`. Return short,
        # human-readable notes. Parsing lives here, in code — never in the LLM.
        return []
```

Guarantees:

- `build_command` returns argv (no shell). Output-file tools use the
  `{OUTFILE}` marker; the base class allocates a temp path and reads it back into
  `ToolResult.output_file`.
- `parse` is the only place tool output becomes state. It must be pure with
  respect to I/O (no network, no execution).
- The registry never lets a plugin shadow a built-in adapter, and a plugin that
  raises on load is logged and skipped — it cannot take down the core.

## Safety model (`breachload.safety`)

The safety layer is deterministic and is never delegated to the model.

- `Risk` (IntEnum, ordered): `PASSIVE < RECON < ACTIVE < INTRUSIVE < EXPLOIT <
  DESTRUCTIVE`. These values are stable.
- `Scope.allows(target) -> bool` — a target is permitted only if it is inside an
  allowed network/domain and not excluded. Default-deny.
- `extract_targets(args) -> set[str]` — pulls every IP / host / URL-host /
  SMB-UNC-authority / `host:port` out of a command's arguments, so scope can be
  enforced before execution.
- `Validator.check(command, risk) -> Decision` runs three gates in order:
  1. binary allowlist (only registered tools),
  2. shell-metacharacter guard (argv only; injection attempt otherwise),
  3. scope (every extracted target must be allowed).
  Then risk gating: at/below `auto_threshold` runs; above it needs confirmation;
  `auto_threshold=None` means confirm everything.

Invariant: **generation is offline and unrestricted; anything that touches a
target is scope- and risk-gated.** Payload/PoC crafting never runs a target-
facing command; delivery always does, and is EXPLOIT-classed.

## Data schemas

- CVE knowledge base (`data/vuln_kb.json` and any `BREACHLOAD_KB` feed):
  `{match: [str], range: str, cve: str, severity: str, name: str}`.
- Payload library (`data/payloads.json`):
  `{id, name, category, platform, tags: [str], template, notes}` with
  `{LHOST} {LPORT} {TARGET} {PORT}` placeholders.
- Attack chains (`data/chains.json`): `{id, name, priority, when, steps}` where
  `when` may contain `service_ports`, `os_contains`, `product_contains`,
  `finding_contains` (all present conditions must hold).
