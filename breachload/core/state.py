"""Structured engagement state.

The whole point of breachload: never reason over raw tool stdout. Every fact
about the target lives here as a typed record, so the LLM sees a clean model
and the parsers (not the LLM) own the ground truth.

Persistence is intentionally simple: the whole state serializes to one JSON
file per engagement. Swap for SQLite once the model stabilizes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Phase(StrEnum):
    SCOPING = "scoping"
    RECON = "recon"
    ENUM = "enumeration"
    VULN = "vuln_analysis"
    EXPLOIT = "exploitation"
    POST = "post_exploitation"
    REPORT = "reporting"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str | None = None          # e.g. "http", "smb"
    product: str | None = None       # e.g. "Apache httpd"
    version: str | None = None
    state: str = "open"
    banner: str | None = None
    notes: list[str] = Field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.port}/{self.protocol}"


class Host(BaseModel):
    address: str                     # IP
    hostnames: list[str] = Field(default_factory=list)
    os_guess: str | None = None
    services: dict[str, Service] = Field(default_factory=dict)  # keyed by "port/proto"
    tags: list[str] = Field(default_factory=list)

    def upsert_service(self, svc: Service) -> None:
        existing = self.services.get(svc.key)
        if existing is None:
            self.services[svc.key] = svc
            return
        # Merge: newer non-null fields win, notes accumulate.
        data = existing.model_dump()
        for field, val in svc.model_dump().items():
            if field == "notes":
                continue
            if val not in (None, "", "open"):
                data[field] = val
        merged = Service(**data)
        merged.notes = list({*existing.notes, *svc.notes})
        self.services[svc.key] = merged


class Credential(BaseModel):
    service_key: str | None = None   # host:port/proto it belongs to
    username: str | None = None
    secret: str | None = None
    kind: str = "password"           # password | hash | key | token
    source: str | None = None        # how we got it
    validated: bool = False


class Finding(BaseModel):
    title: str
    severity: Severity = Severity.INFO
    host: str | None = None
    service_key: str | None = None
    description: str = ""
    evidence: str = ""               # command output / reproduction
    remediation: str = ""
    cve: list[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=_now)


class ActionRecord(BaseModel):
    """One decision+execution cycle, for audit and reporting."""
    phase: Phase
    tool: str
    command: list[str]
    rationale: str = ""              # why the agent chose this (LLM or heuristic)
    started_at: str = Field(default_factory=_now)
    exit_code: int | None = None
    approved: bool = True            # False if blocked/denied by safety layer


class EngagementState(BaseModel):
    name: str
    phase: Phase = Phase.SCOPING
    hosts: dict[str, Host] = Field(default_factory=dict)  # keyed by address
    credentials: list[Credential] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    history: list[ActionRecord] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now)

    # --- mutation helpers ---------------------------------------------------
    def upsert_host(self, address: str) -> Host:
        host = self.hosts.get(address)
        if host is None:
            host = Host(address=address)
            self.hosts[address] = host
        return host

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def record_action(self, action: ActionRecord) -> None:
        self.history.append(action)

    def has_action(self, tool: str, needle: str) -> bool:
        """True if `tool` has already been run against a command containing `needle`.

        Lets the planner avoid re-running the same tool on the same target.
        """
        for a in self.history:
            if a.tool == tool and any(needle in tok for tok in a.command):
                return True
        return False

    # --- persistence --------------------------------------------------------
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> EngagementState:
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def summary(self) -> str:
        """Compact, LLM-friendly view of what we know. No raw output."""
        lines = [f"Engagement '{self.name}' — phase: {self.phase}"]
        for host in self.hosts.values():
            svcs = ", ".join(
                f"{s.key} {s.name or '?'} {s.product or ''} {s.version or ''}".strip()
                for s in sorted(host.services.values(), key=lambda s: s.port)
            )
            os_ = host.os_guess or "os?"
            lines.append(f"  {host.address} [{os_}]: {svcs or 'no services yet'}")
        if self.credentials:
            lines.append(f"  credentials: {len(self.credentials)} collected")
        if self.findings:
            lines.append(f"  findings: {len(self.findings)}")
        return "\n".join(lines)
