"""netexec (nxc) adapter — SMB host + Active Directory enrichment.

An unauthenticated `nxc smb <target>` reveals the NetBIOS name, OS, SMB signing
and — crucially on a Domain Controller — the AD domain. That domain feeds the
correlator's DC detection and the whole AD attack-chain playbook. With
credentials it also enumerates shares and users. Parsing is defensive because
netexec's line format shifts between versions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import Credential, EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

# Banner: SMB <ip> 445 <NETBIOS> [*] <OS> (name:X) (domain:Y) (signing:Z)
_BANNER_RE = re.compile(r"^SMB\s+(\S+)\s+\d+\s+(\S+)\s+\[\*\]\s+(.+)$", re.MULTILINE)
_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.IGNORECASE)
_OS_RE = re.compile(r"^(.*?)\s*\(name:", re.IGNORECASE)
# Valid login: SMB <ip> 445 <HOST> [+] domain\user:pass (Pwn3d!)
_CRED_RE = re.compile(
    r"^SMB\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+([^\\/]+)[\\/]([^:]+):(\S*?)\s*(\(Pwn3d!\))?$",
    re.MULTILINE)
# A share row:  SMB  ip  445  HOST  ShareName   READ,WRITE   Remark
_SHARE_RE = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9$._-]+)\s+(READ|WRITE|READ,WRITE)\b",
                       re.MULTILINE)


@dataclass
class NetexecAdapter(ToolAdapter):
    name: str = "netexec"
    binary: str = "nxc"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["smb", "ad", "enumeration"]

    def build_command(self, target: str, *, protocol: str = "smb",
                      user: str | None = None, password: str | None = None,
                      extra: list[str] | None = None) -> list[str]:
        cmd = ["nxc", protocol, target]
        if user is not None:
            cmd += ["-u", user, "-p", password or ""]
        return cmd + (extra or [])

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        text = result.stdout or ""
        notes: list[str] = []

        for ip, netbios, info in _BANNER_RE.findall(text):
            if "(name:" not in info:      # skip [*] status lines (e.g. "Enumerated shares")
                continue
            host = state.upsert_host(ip)
            os_m = _OS_RE.match(info)
            if os_m and not host.os_guess:
                host.os_guess = os_m.group(1).strip()
            if netbios and netbios != ip and netbios not in host.hostnames:
                host.hostnames.append(netbios)
            dom = _DOMAIN_RE.search(info)
            if dom:
                domain = dom.group(1).strip().lower()
                # WORKGROUP (or the host's own name) is not an AD domain — don't tag
                # it, or the AD chains would try authenticated enum against a
                # standalone host.
                if (domain not in ("workgroup", netbios.lower())
                        and f"domain:{domain}" not in host.tags):
                    host.tags.append(f"domain:{domain}")
            host.upsert_service(Service(port=445, name="microsoft-ds", state="open"))
            notes.append(f"{ip} {netbios} "
                         f"{'domain=' + dom.group(1) if dom else 'workgroup'}".strip())

        for domain, user, pw, pwned in _CRED_RE.findall(text):
            state.credentials.append(Credential(
                username=user, secret=pw or None, kind="password",
                source="netexec", validated=True))
            note = f"valid: {domain}\\{user}"
            if pwned:
                note += " (admin!)"
                state.add_finding(Finding(
                    title=f"Administrative access as {domain}\\{user}",
                    severity=Severity.HIGH,
                    description="netexec reported Pwn3d! — local admin on this host."))
            notes.append(note)

        for share, perm in dict.fromkeys(_SHARE_RE.findall(text)):
            notes.append(f"share {share} ({perm})")

        return notes or [f"netexec: nothing parsed (exit {result.exit_code})"]
