"""Redis adapter - detects an unauthenticated Redis instance via redis-cli INFO.

An unauthenticated Redis is high-impact: it often leads to RCE (module load,
cron/authorized_keys write via CONFIG SET). Read-only probe here (INFO), so
RECON risk; exploitation stays a separate, gated step.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class RedisAdapter(ToolAdapter):
    name: str = "redis"
    binary: str = "redis-cli"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["redis", "enumeration"]

    def build_command(self, target: str, *, port: int = 6379) -> list[str]:
        self._target = target
        self._port = port
        return ["redis-cli", "-h", target, "-p", str(port), "--no-auth-warning",
                "INFO", "server"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 6379)
        text = result.stdout or ""
        low = text.lower()
        # If auth is required, INFO returns a NOAUTH error instead of server info.
        if "noauth" in low or "authentication required" in low:
            return ["redis: authentication required (not unauth-accessible)"]
        if "redis_version" not in low:
            return [f"redis: no usable response (exit {result.exit_code})"]

        ver = None
        m = re.search(r"redis_version:(\S+)", text)
        if m:
            ver = m.group(1)
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="redis", product="Redis",
                                        version=ver, state="open"))
            state.add_finding(Finding(
                title="Unauthenticated Redis access",
                severity=Severity.HIGH, host=target, service_key=f"{port}/tcp",
                description=f"Redis {ver or '?'} responds to INFO without auth. "
                            "Commonly escalates to RCE via CONFIG SET "
                            "(cron/authorized_keys write) or MODULE LOAD.",
                evidence=text[:300],
            ))
        return [f"redis: UNAUTH access, version {ver or '?'}"]
