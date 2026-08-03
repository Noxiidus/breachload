"""Cross-service correlation.

Rules that reason over combinations of state — the kind of leads a human notices
by looking at the whole picture rather than one service. Each rule inspects a
host and yields findings. Add rules here as patterns emerge.
"""

from __future__ import annotations

import re

from ..core.state import EngagementState, Finding, Host, Severity

# Legacy Windows versions historically vulnerable to MS17-010 (EternalBlue).
# Word-bounded so a bare "7" doesn't match build numbers like "windows (17763)".
_LEGACY_WINDOWS = ("xp", "vista", "7", "2003", "2008")
_LEGACY_RE = re.compile(
    r"(?<!\d)(?:" + "|".join(re.escape(t) for t in _LEGACY_WINDOWS) + r")(?!\d)"
)
_SMB_PORTS = (139, 445)


class Correlator:
    def findings_for(self, state: EngagementState) -> list[Finding]:
        out: list[Finding] = []
        for host in state.hosts.values():
            out += self._eternalblue_candidate(host)
            out += self._cleartext_and_anon(host)
        return out

    def _eternalblue_candidate(self, host: Host) -> list[Finding]:
        os_ = (host.os_guess or "").lower()
        if not os_ or "windows" not in os_:
            return []
        ports = {s.port for s in host.services.values()}
        if not (ports & set(_SMB_PORTS)):
            return []
        if not _LEGACY_RE.search(os_):
            return []
        return [Finding(
            title=f"MS17-010 (EternalBlue) candidate on {host.address}",
            severity=Severity.HIGH,
            host=host.address,
            service_key="445/tcp",
            description="Legacy Windows with SMB exposed; verify MS17-010 patch state "
                        "before considering exploitation.",
            cve=["CVE-2017-0144"],
            remediation="Apply MS17-010; disable SMBv1.",
        )]

    def _cleartext_and_anon(self, host: Host) -> list[Finding]:
        out: list[Finding] = []
        for svc in host.services.values():
            name = (svc.name or "").lower()
            is_ftp = svc.port == 21 or name == "ftp"
            is_telnet = svc.port == 23 or name == "telnet"
            if is_ftp or is_telnet:
                proto = "FTP" if is_ftp else "Telnet"
                out.append(Finding(
                    title=f"Cleartext {proto} service on {host.address}",
                    severity=Severity.LOW,
                    host=host.address,
                    service_key=svc.key,
                    description=f"{proto} transmits credentials in cleartext.",
                    remediation="Replace with an encrypted alternative (SFTP/SSH).",
                ))
            if is_ftp and any("anon" in n.lower() for n in svc.notes):
                out.append(Finding(
                    title=f"Anonymous FTP allowed on {host.address}",
                    severity=Severity.MEDIUM,
                    host=host.address,
                    service_key=svc.key,
                    description="Anonymous FTP login is permitted.",
                    remediation="Disable anonymous FTP access.",
                ))
        return out
