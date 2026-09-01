# Custom Adapters

Ship a new scanner without touching breachload's source. Two paths:

- **In-tree** — add a file under `breachload/tools/` and register it in
  `tools/registry.py`. For adapters everyone should get.
- **Plugin** — publish a Python package that exposes your adapter through
  the `breachload.tools` entry-point group. For private / experimental / org-
  specific tools.

Both use the same contract: `ToolAdapter`.

## The contract

```python
from dataclasses import dataclass
from breachload.tools.base import ToolAdapter, ToolResult
from breachload.core.state import EngagementState
from breachload.safety.validator import Risk


@dataclass
class MyToolAdapter(ToolAdapter):
    name: str = "mytool"                    # the tool key (used everywhere)
    binary: str = "mytool"                  # the executable on PATH
    risk: Risk = Risk.RECON                 # RECON / ACTIVE / INTRUSIVE / EXPLOIT / DESTRUCTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "fingerprint"]

    def build_command(self, target: str, **kwargs) -> list[str]:
        # Return the argv (NO shell, NO metacharacters). Any `{OUTFILE}` marker
        # will be replaced by a temp path breachload manages for you.
        return ["mytool", "--json", target]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        # Turn stdout / output_file into structured state updates.
        # Return short notes for the live stream.
        return [f"mytool: {result.exit_code}"]
```

Rules the safety layer enforces at run time:

- `binary` must be on your PATH; missing binary = graceful skip.
- `build_command` returns argv. **Any shell metacharacter** in a token
  (`; | & $ ` \` > < newline`) is refused before the tool runs.
- The command is scope-checked — every host/URL argument must be inside the
  engagement's `targets`.

## Path A — in-tree

```python
# breachload/tools/mytool.py
```

Then in `breachload/tools/registry.py`:

```python
from .mytool import MyToolAdapter
# in default_registry(...):
adapters = [ ..., MyToolAdapter(), ]
```

Add a `pytest` test — a good one asserts `build_command` output is validator-
clean (`test_registered_commands_pass_validator` already sweeps everything;
your adapter joins it automatically).

## Path B — plugin (recommended for third-party)

In your package's `pyproject.toml`:

```toml
[project.entry-points."breachload.tools"]
mytool = "my_pkg.adapters:MyToolAdapter"
```

Install the package into the same environment as breachload. `default_registry()`
discovers it on startup:

```
breachload doctor --self-test
# ... your adapter shows up alongside the built-ins
```

A broken plugin (import error, wrong type) is logged and skipped — it never
takes down the core. Built-in adapters are never shadowed by a plugin of
the same name.

## OUTFILE convention

Some tools only emit machine-readable output to a file, not stdout. Return
`{OUTFILE}` in your argv and set:

```python
output_file_suffix: str | None = ".json"
```

The base runner allocates a temp path, substitutes it in argv, reads the
file back into `ToolResult.output_file`, and cleans up. See
`tools/enum4linux.py` for a canonical example.

## Parse conventions

- Append short strings to `notes` on the relevant `Service` — parsers
  downstream (webcve, adchain, class detectors) read these.
- Add findings via `state.add_finding(Finding(...))` with severity + evidence.
- Add credentials via `state.credentials.append(Credential(...))`.
- Never crash on unexpected input — return a note like
  `"mytool: no output"` and move on. The fuzz harness will find any panic
  path anyway.

## Testing

- `tests/test_adapters.py::test_registered_commands_pass_validator` — all
  registered adapters get their default argv checked against the validator
  automatically.
- Add a test that hands your adapter a canonical stdout blob and asserts
  the resulting state changes. Aim for parse tests over live-tool tests
  (deterministic + fast).
