"""MSSQL adapter — tests a default `sa` login via netexec (nxc).

Reuses nxc's mssql module (the binary is already in the allowlist) to probe the
classic `sa` account with a blank password. A successful login is HIGH: sa often
means RCE via xp_cmdshell. ACTIVE risk (single auth attempt).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import Credential, EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class MssqlAdapter(ToolAdapter):
    name: str = "mssql"
    binary: str = "nxc"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["mssql", "database", "enumeration"]

    def build_command(self, target: str, *, port: int = 1433, user: str = "sa") -> list[str]:
        self._target = target
        self._port = port
        self._user = user
        # -p '' is an explicit blank password; --local-auth for a local SQL login.
        return ["nxc", "mssql", target, "-u", user, "-p", "", "--local-auth",
                "--port", str(port)]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 1433)
        user = getattr(self, "_user", "sa")
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        # nxc marks a successful auth with a green [+]; failure with [-].
        success = bool(re.search(r"\[\+\].*" + re.escape(user), text, re.IGNORECASE)) \
            or "pwn3d" in text.lower()
        if not success:
            if "[-]" in text:
                return [f"mssql: login failed for {user} (blank password rejected)"]
            return [f"mssql: no usable response (exit {result.exit_code})"]

        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="ms-sql-s", product="Microsoft SQL Server",
                                        state="open"))
            state.credentials.append(Credential(
                service_key=f"{target}:{port}/tcp", username=user, secret="",
                kind="password", source="mssql blank sa login", validated=True))
            state.add_finding(Finding(
                title="MSSQL blank sa login",
                severity=Severity.HIGH, host=target, service_key=f"{port}/tcp",
                description=f"MSSQL on {port} accepts '{user}' with no password. "
                            "sa typically means RCE via xp_cmdshell (enable it, then "
                            "run commands as the SQL service account).",
                evidence=text.strip()[:300],
                exploit=f"nxc mssql {target} -u {user} -p '' --local-auth -x whoami",
            ))
        return [f"mssql: {user} blank-password login OK"]
