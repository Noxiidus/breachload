"""nuclei adapter — templated vulnerability scanning.

Each match becomes a Finding with mapped severity. Uses nuclei's JSONL output
(one JSON object per line) so parsing is line-oriented and robust.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.state import EngagementState, Finding, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class NucleiAdapter(ToolAdapter):
    name: str = "nuclei"
    binary: str = "nuclei"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "vuln-scan"]

    def build_command(
        self,
        target: str,
        *,
        severity: str | None = None,
        tags: str | None = None,
    ) -> list[str]:
        cmd = ["nuclei", "-u", _as_url(target), "-jsonl", "-silent"]
        if severity:
            cmd += ["-severity", severity]
        if tags:
            cmd += ["-tags", tags]
        return cmd

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        notes: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = m.get("info", {}) or {}
            sev = _SEVERITY.get((info.get("severity") or "info").lower(), Severity.INFO)
            matched = m.get("matched-at") or m.get("host") or ""
            host_name = urlparse(_as_url(matched)).hostname or matched
            title = info.get("name") or m.get("template-id") or "nuclei match"
            cve_ids = (info.get("classification", {}) or {}).get("cve-id") or []

            if host_name:
                state.upsert_host(host_name)
            state.add_finding(Finding(
                title=title,
                severity=sev,
                host=host_name or None,
                description=info.get("description", "") or "",
                evidence=matched,
                cve=[c.upper() for c in cve_ids],
            ))
            notes.append(f"[{sev.value}] {title} @ {matched}")
        return notes or ["nuclei: no matches"]


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"
