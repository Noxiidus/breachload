"""Command validation gate.

The LLM proposes a command; this gate decides whether it may run. Three checks,
all deterministic:

  1. Binary allowlist — only known, registered tools.
  2. Scope — every target in the args must be in scope.
  3. Risk class — destructive/intrusive commands require confirmation even in
     full-auto mode (or are blocked entirely below the configured threshold).

Nothing here trusts the model. If the model asks for `rm`, a shell pipe, or a
target outside scope, it is denied and logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .scope import Scope, extract_targets


class Risk(IntEnum):
    PASSIVE = 0      # whois, dns, cert lookups
    RECON = 1        # nmap discovery, whatweb — noisy but non-intrusive
    ACTIVE = 2       # dir brute, nuclei, enum — touches the target actively
    INTRUSIVE = 3    # brute-force auth, sqlmap dumping
    EXPLOIT = 4      # exploit execution, shells, writes
    DESTRUCTIVE = 5  # anything that can damage/DoS the target


# Shell metacharacters that must never appear in a proposed argv token —
# commands run via argv list (no shell), so these signal an injection attempt.
_FORBIDDEN = (";", "|", "&", "$(", "`", ">", "<", "\n")


@dataclass
class Decision:
    allowed: bool
    needs_confirmation: bool
    reason: str
    risk: Risk


class Validator:
    def __init__(
        self,
        scope: Scope,
        allowed_binaries: set[str],
        auto_threshold: Risk = Risk.ACTIVE,
    ) -> None:
        self.scope = scope
        self.allowed_binaries = allowed_binaries
        # Actions at or below this risk run automatically in full-auto mode;
        # anything above requires explicit human confirmation.
        self.auto_threshold = auto_threshold

    def check(self, command: list[str], risk: Risk) -> Decision:
        if not command:
            return Decision(False, False, "empty command", risk)

        binary = command[0]
        if binary not in self.allowed_binaries:
            return Decision(False, False, f"binary '{binary}' not in allowlist", risk)

        for token in command:
            if any(bad in token for bad in _FORBIDDEN):
                return Decision(False, False, f"forbidden shell metacharacter in '{token}'", risk)

        targets = extract_targets(command[1:])
        out_of_scope = [t for t in targets if not self.scope.allows(t)]
        if out_of_scope:
            joined = ", ".join(out_of_scope)
            return Decision(False, False, f"out-of-scope target(s): {joined}", risk)

        if risk > self.auto_threshold:
            return Decision(
                True, True,
                f"risk {risk.name} above auto threshold {self.auto_threshold.name}",
                risk,
            )
        return Decision(True, False, "within scope and auto threshold", risk)
