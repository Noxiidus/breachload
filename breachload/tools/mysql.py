"""MySQL/MariaDB adapter - tests for a blank/weak root login.

Default or blank database credentials are a recurring foothold. Probes a single
common login (root with no password) using the mysql client; a successful
connection is a HIGH finding. One auth attempt, not a brute-force -> ACTIVE risk.
No shell metacharacters (the query has no trailing ';').
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import Credential, EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class MysqlAdapter(ToolAdapter):
    name: str = "mysql"
    binary: str = "mysql"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["mysql", "database", "enumeration"]

    def build_command(self, target: str, *, port: int = 3306, user: str = "root") -> list[str]:
        self._target = target
        self._port = port
        self._user = user
        # --password= is an explicit blank password (no prompt). SHOW DATABASES has
        # no trailing ';' so the argv carries no shell metacharacter.
        return ["mysql", "-h", target, "-P", str(port), "-u", user,
                "--password=", "--connect-timeout=8", "-e", "SHOW DATABASES"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 3306)
        user = getattr(self, "_user", "root")
        text = result.stdout or ""
        low = (text + " " + (result.stderr or "")).lower()
        if "access denied" in low:
            return [f"mysql: access denied for {user} (blank password rejected)"]
        if "can't connect" in low or "couldn't connect" in low or "timeout" in low:
            return [f"mysql: could not connect (exit {result.exit_code})"]
        if "information_schema" not in low and "database" not in low:
            return [f"mysql: no usable response (exit {result.exit_code})"]

        dbs = [ln.strip() for ln in text.splitlines()
               if ln.strip() and ln.strip().lower() != "database"]
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="mysql", product="MySQL", state="open"))
            state.credentials.append(Credential(
                service_key=f"{target}:{port}/tcp", username=user, secret="",
                kind="password", source="mysql blank-password login", validated=True))
            state.add_finding(Finding(
                title="MySQL blank/weak root login",
                severity=Severity.HIGH, host=target, service_key=f"{port}/tcp",
                description=f"MySQL on {port} accepts '{user}' with no password "
                            f"({len(dbs)} databases visible). Read app secrets, or "
                            "escalate via SELECT ... INTO OUTFILE / UDF if FILE priv "
                            "is granted.",
                evidence="\n".join(dbs[:30]),
            ))
        return [f"mysql: {user} blank-password login OK - databases: "
                f"{', '.join(dbs[:8]) or '(none listed)'}"]
