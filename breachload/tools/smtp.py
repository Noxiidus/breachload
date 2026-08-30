"""SMTP adapter - username enumeration via VRFY (smtp-user-enum).

Valid usernames leaked over SMTP VRFY/RCPT seed password spraying and reveal
system users. Uses smtp-user-enum with a short built-in username list; ACTIVE risk
(it probes the mail server actively). Skips gracefully when the tool/list is absent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

# Common short username list shipped with SecLists; the operator can point at a
# bigger one by editing the engagement. Kept small so the default run is quick.
_DEFAULT_USERLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"


@dataclass
class SmtpAdapter(ToolAdapter):
    name: str = "smtp"
    binary: str = "smtp-user-enum"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["smtp", "enumeration"]

    def build_command(self, target: str, *, port: int = 25,
                      userlist: str = _DEFAULT_USERLIST) -> list[str]:
        self._target = target
        self._port = port
        # -M VRFY: use the VRFY verb. -U userlist, -t target host, -p port.
        return ["smtp-user-enum", "-M", "VRFY", "-U", userlist,
                "-t", target, "-p", str(port)]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 25)
        text = result.stdout or ""
        low = (text + " " + (result.stderr or "")).lower()
        if "no such file" in low or "not found" in low or "unable to open" in low:
            return ["smtp: username list not found - install SecLists or pass a list"]

        # smtp-user-enum prints "<user>@<host> exists" (or "... found") per hit.
        users: list[str] = []
        for line in text.splitlines():
            m = re.match(r"([A-Za-z0-9._-]+)@\S+\s+(?:exists|found)", line.strip())
            if m:
                users.append(m.group(1))
        users = list(dict.fromkeys(users))

        if not users:
            return [f"smtp: no users enumerated (exit {result.exit_code})"]
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="smtp", state="open"))
            state.add_finding(Finding(
                title="SMTP username enumeration (VRFY)",
                severity=Severity.MEDIUM, host=target, service_key=f"{port}/tcp",
                description=f"SMTP on {port} leaks valid usernames via VRFY "
                            f"({len(users)} found). Feed them into password spraying "
                            "against SSH/SMB/web-login.",
                evidence=", ".join(users[:50]),
            ))
        return [f"smtp: enumerated {len(users)} user(s): {', '.join(users[:10])}"]
