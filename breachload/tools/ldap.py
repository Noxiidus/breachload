"""LDAP adapter - tests for an anonymous bind and reads the naming contexts.

An anonymous LDAP bind often leaks the domain structure and, on many boxes, user
objects with descriptions that hold passwords. Read-only base query here (RECON);
a full dump is a follow-up the suggestion names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

_NC_RE = re.compile(r"namingContexts:\s*(.+)", re.IGNORECASE)


@dataclass
class LdapAdapter(ToolAdapter):
    name: str = "ldap"
    binary: str = "ldapsearch"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["ldap", "enumeration"]

    def build_command(self, target: str, *, port: int = 389) -> list[str]:
        self._target = target
        self._port = port
        # -x simple auth, -s base + namingContexts is the classic anon-bind probe.
        return ["ldapsearch", "-x", "-H", f"ldap://{target}:{port}", "-s", "base",
                "namingContexts"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 389)
        text = result.stdout or ""
        contexts = [m.strip() for m in _NC_RE.findall(text)]
        low = (text + " " + (result.stderr or "")).lower()
        if not contexts:
            if "can't contact" in low or "timed out" in low:
                return [f"ldap: could not connect (exit {result.exit_code})"]
            return ["ldap: anonymous bind returned no naming contexts"]

        domain = ""
        m = re.search(r"dc=([^,\s]+(?:,dc=[^,\s]+)*)", contexts[0], re.IGNORECASE)
        if m:
            domain = ".".join(p.split("=", 1)[1] for p in m.group(0).split(","))
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="ldap", state="open"))
            if domain and f"domain:{domain}" not in host.tags:
                host.tags.append(f"domain:{domain}")
            state.add_finding(Finding(
                title="Anonymous LDAP bind allowed",
                severity=Severity.MEDIUM, host=target, service_key=f"{port}/tcp",
                description=f"LDAP on {port} permits an anonymous bind "
                            f"(naming contexts: {', '.join(contexts[:3])}). Dump users "
                            "and look for passwords in description/info attributes.",
                evidence="\n".join(contexts[:5]),
                exploit=f"ldapsearch -x -H ldap://{target}:{port} -b '{contexts[0]}' "
                        "'(objectClass=user)'",
            ))
        return [f"ldap: anonymous bind OK - {len(contexts)} naming context(s)"
                + (f", domain {domain}" if domain else "")]
