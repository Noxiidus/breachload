# Writing Adapters

Adapters are the main extension point. An adapter teaches breachload how to run
one tool and how to fold its output into structured state.

## Contract

Subclass `ToolAdapter` (`tools/base.py`) and implement two methods:

```python
from dataclasses import dataclass
from breachload.tools.base import ToolAdapter, ToolResult
from breachload.core.state import EngagementState
from breachload.safety.validator import Risk


@dataclass
class WhatWebAdapter(ToolAdapter):
    name: str = "whatweb"
    binary: str = "whatweb"
    risk: Risk = Risk.RECON

    def __post_init__(self):
        if not self.capabilities:
            self.capabilities = ["http", "fingerprint"]

    def build_command(self, target: str, **kwargs) -> list[str]:
        # argv list only — never a shell string.
        return ["whatweb", "--log-json=-", "--no-errors", target]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        # Parse machine-readable output into state; return short notes.
        ...
        return notes
```

## Rules

1. **argv, not shell.** `build_command` returns a list. No `;`, pipes, or
   redirects — the validator rejects them anyway.
2. **Parse in code.** Prefer JSON/XML output flags. Never hand raw stdout to the
   LLM to interpret.
3. **Honest risk class.** If it can brute-force, dump, exploit, or damage, it is
   `INTRUSIVE` or higher so the safety layer gates it. Getting this wrong is the
   one mistake that breaks the autonomy model.
4. **Register it.** Add to `default_registry()` in `tools/registry.py`. This also
   authorizes its binary in the validator allowlist.
5. **Declare capabilities.** Free-form tags the planner matches per phase
   (e.g. `"http"`, `"smb"`, `"port-scan"`).

## Testing

Feed a captured sample of the tool's real output through `parse()` and assert the
resulting state. See `tools/nmap.py` for the XML reference and mirror its style.
