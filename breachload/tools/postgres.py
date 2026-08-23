"""PostgreSQL adapter — tests for a trust/blank postgres login.

Many misconfigured Postgres instances allow the built-in `postgres` superuser with
no password (trust auth). Probes one login with the psql client (`-w` = never
prompt), reporting a successful connect as HIGH. ACTIVE risk (single auth attempt).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import Credential, EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class PostgresAdapter(ToolAdapter):
    name: str = "postgres"
    binary: str = "psql"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["postgresql", "database", "enumeration"]

    def build_command(self, target: str, *, port: int = 5432, user: str = "postgres") -> list[str]:
        self._target = target
        self._port = port
        self._user = user
        # -w never prompts for a password (non-interactive-safe). SELECT version()
        # has no trailing ';', so no shell metacharacter in the argv.
        return ["psql", "-h", target, "-p", str(port), "-U", user, "-w",
                "-c", "SELECT version()"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 5432)
        user = getattr(self, "_user", "postgres")
        text = result.stdout or ""
        low = (text + " " + (result.stderr or "")).lower()
        if "authentication failed" in low or "no password supplied" in low:
            return [f"postgres: authentication failed for {user}"]
        if "could not connect" in low or "connection refused" in low or "timeout" in low:
            return [f"postgres: could not connect (exit {result.exit_code})"]
        if "postgresql" not in low:
            return [f"postgres: no usable response (exit {result.exit_code})"]

        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="postgresql", product="PostgreSQL",
                                        state="open"))
            state.credentials.append(Credential(
                service_key=f"{target}:{port}/tcp", username=user, secret="",
                kind="password", source="postgres trust/blank login", validated=True))
            state.add_finding(Finding(
                title="PostgreSQL trust/blank login",
                severity=Severity.HIGH, host=target, service_key=f"{port}/tcp",
                description=f"PostgreSQL on {port} accepts '{user}' with no password. "
                            "As superuser you can read files (pg_read_file), and often "
                            "reach RCE via COPY ... FROM PROGRAM.",
                evidence=text.strip()[:300],
            ))
        return [f"postgres: {user} passwordless login OK"]
