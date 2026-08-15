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
_DOMAIN_RE = re.compile(r"Domain:\s*([A-Za-z0-9.\-]+)", re.IGNORECASE)


def _guess_domain(host: Host) -> str | None:
    """Best-effort AD domain from LDAP/Kerberos service info or an FQDN hostname."""
    blobs: list[str] = list(host.hostnames)
    for svc in host.services.values():
        blobs += [svc.product or "", svc.version or "", svc.banner or "", *svc.notes]
    for blob in blobs:
        m = _DOMAIN_RE.search(blob)
        if m:
            dom = re.sub(r"0$", "", m.group(1).strip(" .,")).lower()  # nmap adds a stray "0"
            if "." in dom:
                return dom
    for hostname in host.hostnames:                    # dc01.corp.local -> corp.local
        parts = hostname.strip(".").split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:]).lower()
    return None


class Correlator:
    def findings_for(self, state: EngagementState) -> list[Finding]:
        out: list[Finding] = []
        for host in state.hosts.values():
            out += self._eternalblue_candidate(host)
            out += self._domain_controller(host)
            out += self._cleartext_and_anon(host)
        return out

    def _domain_controller(self, host: Host) -> list[Finding]:
        """Kerberos + LDAP on one host is a strong Domain Controller signal — the
        entry point to the whole Active Directory attack surface."""
        ports = {s.port for s in host.services.values()}
        if 88 not in ports or not ({389, 636, 3268} & ports):
            return []
        domain = _guess_domain(host)
        desc = "Kerberos and LDAP indicate an Active Directory Domain Controller."
        if domain:
            desc += f" Domain: {domain}."
        desc += (" Enumerate the domain (authenticated once you have any credential) and "
                 "map privilege-escalation paths with BloodHound / certipy.")
        if "dc" not in host.tags:
            host.tags.append("dc")
        if domain and f"domain:{domain}" not in host.tags:
            host.tags.append(f"domain:{domain}")
        return [Finding(
            title=f"Active Directory Domain Controller on {host.address}",
            severity=Severity.INFO, host=host.address, service_key="88/tcp",
            description=desc,
        )]

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
