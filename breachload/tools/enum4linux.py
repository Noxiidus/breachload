"""enum4linux-ng adapter - SMB / NetBIOS / host enumeration.

enum4linux-ng writes JSON to a file (``-oJ <prefix>`` -> ``<prefix>.json``), so
this adapter uses the OUTFILE_MARKER mechanism and parses the file, falling back
to stdout if the file is missing. The JSON schema varies by version, so parsing
is deliberately defensive.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..core.state import Credential, EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

_READ_HINTS = ("READ", "OK")


@dataclass
class Enum4linuxAdapter(ToolAdapter):
    name: str = "enum4linux-ng"
    binary: str = "enum4linux-ng"
    risk: Risk = Risk.ACTIVE
    output_file_suffix: str | None = ".json"

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["smb", "netbios", "enumeration"]

    def build_command(self, target: str, *, aggressive: bool = True) -> list[str]:
        # -A = all simple enumeration; -oJ writes JSON to <marker>.json.
        cmd = ["enum4linux-ng"]
        if aggressive:
            cmd.append("-A")
        cmd += ["-oJ", "{OUTFILE}", target]
        return cmd

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        data = _load(result)
        if data is None:
            return [f"enum4linux-ng: no parseable JSON (exit {result.exit_code})"]

        target = data.get("target", {}) or {}
        host_name = target.get("host") or _first_host(data)
        if not host_name:
            return ["enum4linux-ng: no host in output"]
        host = state.upsert_host(host_name)
        notes: list[str] = []

        # SMB service + OS.
        os_info = data.get("os_info", {}) or {}
        os_label = os_info.get("OS") or os_info.get("Native OS")
        if os_label:
            host.os_guess = host.os_guess or os_label
        workgroup = target.get("workgroup") or data.get("workgroup")
        svc = Service(port=445, name="microsoft-ds", state="open")
        if workgroup:
            svc.notes.append(f"workgroup: {workgroup}")
        host.upsert_service(svc)

        # Null session - a real finding.
        sessions = data.get("sessions", {}) or {}
        if _truthy(sessions.get("Null session") or sessions.get("null_session")):
            state.add_finding(Finding(
                title=f"SMB null session allowed on {host_name}",
                severity=Severity.MEDIUM, host=host_name, service_key="445/tcp",
                description="Anonymous (null) SMB session permitted, enabling enumeration.",
                remediation="Restrict anonymous access (RestrictAnonymous / RestrictNullSessAccess "
                            "registry keys).",
            ))
            notes.append(f"{host_name}: NULL SESSION allowed")

        # Shares - readable ones are findings.
        shares = data.get("shares", {}) or {}
        for share_name, info in _as_items(shares):
            access = info.get("access") if isinstance(info, dict) else None
            access_list = access if isinstance(access, list) else []
            readable = any(h in " ".join(map(str, access_list)).upper() for h in _READ_HINTS)
            svc.notes.append(f"share {share_name}: {access_list or 'listed'}")
            if readable:
                state.add_finding(Finding(
                    title=f"Readable SMB share '{share_name}' on {host_name}",
                    severity=Severity.LOW, host=host_name, service_key="445/tcp",
                    description=f"Share '{share_name}' is accessible.",
                    evidence=str(info),
                ))
            notes.append(f"{host_name} share: {share_name}")

        # Users - record usernames as (unvalidated) credential leads.
        users = data.get("users", {}) or {}
        usernames = _usernames(users)
        for uname in usernames:
            state.credentials.append(Credential(
                service_key=f"{host_name}:445/tcp", username=uname,
                kind="username", source="enum4linux-ng", validated=False,
            ))
        if usernames:
            notes.append(f"{host_name}: {len(usernames)} users ({', '.join(usernames[:10])})")

        return notes or [f"enum4linux-ng: enumerated {host_name}"]


def _load(result: ToolResult) -> dict | None:
    for blob in (result.output_file, result.stdout):
        if not blob:
            continue
        try:
            data = json.loads(blob)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            continue
    return None


def _as_items(obj):
    if isinstance(obj, dict):
        return obj.items()
    if isinstance(obj, list):
        return enumerate(obj)
    return []


def _usernames(users) -> list[str]:
    names: list[str] = []
    for _, info in _as_items(users):
        if isinstance(info, dict):
            name = info.get("username") or info.get("name")
            if name:
                names.append(str(name))
        elif isinstance(info, str):
            names.append(info)
    return names


def _first_host(data: dict) -> str | None:
    for key in ("host", "ip", "target_ip"):
        val = data.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _truthy(val) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "yes", "1", "allowed", "ok")
    return bool(val)
