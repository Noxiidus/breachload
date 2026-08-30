"""Scope enforcement - the hard boundary of an autonomous pentest agent.

Every target an action touches is checked here, in deterministic code, BEFORE
execution. The LLM is never trusted to respect scope on its own. An out-of-scope
target is a hard block, not a warning.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class Scope:
    """Allowlist of targets. Anything not explicitly allowed is denied."""

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)          # exact or "*.example.com"
    excluded: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)

    @classmethod
    def from_config(cls, targets: list[str], exclude: list[str] | None = None) -> Scope:
        nets: list = []
        doms: list[str] = []
        for t in targets:
            t = t.strip()
            if not t:
                continue
            net = _try_network(t)
            if net is not None:
                nets.append(net)
            else:
                doms.append(t.lower())
        exc = [n for e in (exclude or []) if (n := _try_network(e)) is not None]
        return cls(networks=nets, domains=doms, excluded=exc)

    def allows(self, target: str) -> bool:
        """True only if target is inside an allowed net/domain and not excluded."""
        ip = _try_ip(target)
        if ip is not None:
            if any(ip in n for n in self.excluded):
                return False
            return any(ip in n for n in self.networks)
        return self._domain_allowed(target.lower())

    def _domain_allowed(self, host: str) -> bool:
        for pattern in self.domains:
            if pattern.startswith("*."):
                if host == pattern[2:] or host.endswith(pattern[1:]):
                    return True
            elif host == pattern:
                return True
        return False


# --- host extraction from arbitrary command args ---------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
# URL host: skip any ``userinfo@`` first, then capture a bracketed IPv6
# (``[::1]``) or a plain host/IPv4. The userinfo (``user:pass@``) must never be
# mistaken for the host, or an out-of-scope host could hide behind an in-scope
# looking credential (``http://in.scope:x@evil.com/``).
_URL_RE = re.compile(r"https?://(?:[^/@\s]*@)?(\[[0-9A-Fa-f:]+\]|[^/:\s]+)", re.IGNORECASE)
# Authority after an SMB/UNC prefix: //host/share or \\host\share (skip userinfo).
_AUTHORITY_RE = re.compile(r"(?://|\\\\)(?:[^/\\@\s]*@)?([a-z0-9.\-]+)", re.IGNORECASE)
# A whole-argument host:port, e.g. evil.com:445 (bare IPs are caught by _IP_RE).
_HOSTPORT_RE = re.compile(r"([a-z0-9.\-]+):\d{1,5}", re.IGNORECASE)


def extract_targets(args: list[str]) -> set[str]:
    """Pull every IP/host/URL-host out of a command's arguments.

    Used to check a proposed command against scope before running it. Matches:
    URLs (``http://host``, ignoring any ``user:pass@`` userinfo), bare IPv4
    anywhere, a bare IPv6 literal as a whole argument, SMB/UNC authorities
    (``//host/share``, ``\\\\host\\share``), a whole-argument ``host:port``, and a
    whole-argument hostname. Hostnames are only taken when the argument really is
    a host - so file paths like ``wordlists/common.txt`` are not misread as
    targets - but a host must never slip through scope just because it is wrapped
    in an SMB path, carries a port, hides behind URL credentials, or is an IPv6
    literal that the IPv4/hostname patterns don't recognise.
    """
    found: set[str] = set()
    for arg in args:
        token = arg.strip()
        for m in _URL_RE.findall(arg):
            found.add(m.strip("[]"))                # unwrap a bracketed IPv6 host
        for m in _IP_RE.findall(arg):
            found.add(m)
        for m in _AUTHORITY_RE.findall(arg):        # //host or \\host
            if _try_ip(m) or _HOST_RE.fullmatch(m):
                found.add(m)
        # A bare IP literal as a whole argument, including IPv6 - which _IP_RE
        # (IPv4-only) and _HOST_RE do not catch, e.g. `nmap dead:beef::1` or a
        # bracketed `[::1]`. Without this an out-of-scope IPv6 target slips past.
        stripped = token.strip("[]")
        if _try_ip(stripped) is not None:
            found.add(stripped)
        host = token
        hostport = _HOSTPORT_RE.fullmatch(token)    # host:port -> host
        if hostport:
            host = hostport.group(1)
        if _HOST_RE.fullmatch(host):
            found.add(host)
    return found


def _try_network(s: str):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def _try_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None
