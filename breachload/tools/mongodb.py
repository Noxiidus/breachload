"""MongoDB adapter — tests for unauthenticated access via mongosh.

A MongoDB with no auth lets anyone list databases and read collections. Probes
with mongosh listing databases; a successful list is HIGH. ACTIVE risk. The eval
string carries no shell metacharacters (no ; | & < > backtick).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class MongoAdapter(ToolAdapter):
    name: str = "mongodb"
    binary: str = "mongosh"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["mongodb", "database", "enumeration"]

    def build_command(self, target: str, *, port: int = 27017) -> list[str]:
        self._target = target
        self._port = port
        return ["mongosh", f"mongodb://{target}:{port}", "--quiet",
                "--eval", "db.adminCommand('listDatabases')"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 27017)
        text = result.stdout or ""
        low = (text + " " + (result.stderr or "")).lower()
        if "requires authentication" in low or "unauthorized" in low:
            return ["mongodb: authentication required (not unauth-accessible)"]
        if "econnrefused" in low or "connect" in low and "failed" in low:
            return [f"mongodb: could not connect (exit {result.exit_code})"]
        if "databases" not in low and "totalsize" not in low:
            return [f"mongodb: no usable response (exit {result.exit_code})"]
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="mongodb", product="MongoDB",
                                        state="open"))
            state.add_finding(Finding(
                title="Unauthenticated MongoDB access",
                severity=Severity.HIGH, host=target, service_key=f"{port}/tcp",
                description=f"MongoDB on {port} lists databases without auth. Dump "
                            "collections for credentials and application data.",
                evidence=text.strip()[:300],
                exploit=f"mongosh 'mongodb://{target}:{port}' --quiet "
                        "--eval 'db.getMongo().getDBNames()'",
            ))
        return [f"mongodb: UNAUTH access on {port}"]
