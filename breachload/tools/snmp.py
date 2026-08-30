"""SNMP adapter - reads an SNMP tree with a default/guessable community.

A readable SNMP service (community `public`) leaks system info, running
processes, installed software, listening ports, and sometimes credentials.
Read-only, so it runs at RECON risk. The target lacks in its own output, so
`build_command` stashes it for `parse` (execution is sequential).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

# OIDs worth surfacing verbatim in notes.
_INTERESTING = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.4.0": "sysContact",
}
# "community" is deliberately excluded - it is an SNMP concept and appears all
# over benign MIB values, so it would flood findings with false positives.
_CRED_HINTS = ("password", "passwd", "pwd", "secret", "cred")


@dataclass
class SnmpAdapter(ToolAdapter):
    name: str = "snmp"
    binary: str = "snmpwalk"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["snmp", "enumeration"]

    def build_command(self, target: str, *, community: str = "public",
                      port: int = 161) -> list[str]:
        self._target = target
        self._port = port
        # -Oqn: quiet numeric OIDs (stable to parse); short timeout/1 retry.
        return ["snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1",
                "-Oqn", f"{target}:{port}"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 161)
        text = result.stdout or ""
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines or "No Response" in text or "Timeout" in text:
            return [f"snmp: no response (community 'public'?) exit {result.exit_code}"]

        notes: list[str] = []
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, protocol="udp", name="snmp", state="open"))

        # Surface named OIDs and any credential-looking values.
        for ln in lines:
            parts = ln.split(" ", 1)
            if len(parts) != 2:
                continue
            oid, val = parts[0].lstrip("."), parts[1].strip()
            label = _INTERESTING.get(oid)
            if label:
                notes.append(f"snmp {label}: {val[:120]}")
            if any(h in val.lower() for h in _CRED_HINTS) and target:
                state.add_finding(Finding(
                    title="SNMP value mentions a credential",
                    severity=Severity.MEDIUM, host=target,
                    service_key=f"{port}/udp",
                    description="An SNMP OID value references a secret; review it.",
                    evidence=ln[:200],
                ))

        if target:
            state.add_finding(Finding(
                title="SNMP readable with community 'public'",
                severity=Severity.MEDIUM, host=target, service_key=f"{port}/udp",
                description=f"SNMP tree is readable with the default community "
                            f"('public'); {len(lines)} OIDs enumerated.",
                evidence="\n".join(lines[:20]),
            ))
        notes.append(f"snmp: {len(lines)} OIDs readable with community 'public'")
        return notes
