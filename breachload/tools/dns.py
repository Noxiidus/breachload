"""DNS adapter - attempt a zone transfer and harvest records.

A misconfigured DNS server that allows AXFR hands over the whole zone: every host,
subdomain, and internal name in one request. It is a classic, high-value early win
(especially on `.htb` domains where the box is its own authoritative NS). This
adapter runs ``dig axfr @<server> <domain>``; on success it folds every A/AAAA
record into new hosts/notes in the engagement state, and flags the transfer itself
as a finding. On refusal it degrades to a quiet note.

Read-only (RECON risk). ``dig`` is the only binary. The domain to transfer comes
from the kwarg, or is inferred when the target is itself a hostname.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

# A dig +noall +answer row: "name.  TTL  IN  A  1.2.3.4"
_ROW_RE = re.compile(
    r"^(?P<name>\S+)\.\s+\d+\s+IN\s+(?P<type>A|AAAA|CNAME|MX|NS|TXT|PTR)\s+(?P<data>.+)$",
    re.IGNORECASE)
_FAIL_HINTS = ("transfer failed", "communications error", "connection refused",
               "no servers could be reached", "; transfer failed")


def _infer_domain(target: str) -> str | None:
    """Use the target as the zone when it is a hostname (not an IP)."""
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        return target if "." in target else None


@dataclass
class DnsAdapter(ToolAdapter):
    name: str = "dns"
    binary: str = "dig"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["dns", "enumeration"]

    def build_command(self, target: str, *, domain: str | None = None,
                      port: int = 53) -> list[str]:
        self._target = target
        self._port = port
        self._domain = domain or _infer_domain(target) or target
        # +noall +answer: just the records; +time/tries bound a dead server fast.
        return ["dig", f"@{target}", "axfr", self._domain,
                "+noall", "+answer", "+time=5", "+tries=1"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        domain = getattr(self, "_domain", "")
        text = result.stdout or ""
        low = text.lower()
        rows = [m.groupdict() for ln in text.splitlines()
                if (m := _ROW_RE.match(ln.strip()))]

        if not rows:
            if any(h in low for h in _FAIL_HINTS):
                return [f"dns: AXFR refused for {domain} (as expected on a hardened NS)"]
            return [f"dns: no zone data for {domain} (exit {result.exit_code})"]

        notes: list[str] = []
        addresses: list[tuple[str, str]] = []   # (name, ip)
        for r in rows:
            name = r["name"].rstrip(".")
            rtype = r["type"].upper()
            data = r["data"].strip().rstrip(".")
            if rtype in ("A", "AAAA"):
                addresses.append((name, data))
            notes.append(f"dns {rtype}: {name} -> {data}"[:140])

        # Fold discovered A/AAAA records into the state as known hosts, tagging the
        # DNS name so later phases can address them by name.
        for name, ip in addresses:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            host = state.upsert_host(ip)
            tag = f"dns-name: {name}"
            if tag not in host.tags:
                host.tags.append(tag)

        if target:
            state.upsert_host(target).upsert_service(
                Service(port=getattr(self, "_port", 53), protocol="tcp",
                        name="dns", state="open"))
            state.add_finding(Finding(
                title=f"DNS zone transfer (AXFR) allowed: {domain}",
                severity=Severity.HIGH, host=target, service_key="53/tcp",
                description=f"The DNS server allows AXFR for '{domain}': the full zone "
                            f"({len(rows)} records, {len(addresses)} hosts) was "
                            "transferred, disclosing the internal namespace.",
                evidence="\n".join(notes[:25]),
                remediation="Restrict zone transfers to authorised secondary servers "
                            "(allow-transfer) only.",
            ))
        notes.append(f"dns: AXFR succeeded for {domain} - {len(addresses)} host(s) found")
        return notes
