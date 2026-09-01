"""nuclei adapter - templated vulnerability scanning.

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
        template_id: str | None = None,
    ) -> list[str]:
        cmd = ["nuclei", "-u", _as_url(target), "-jsonl", "-silent"]
        if severity:
            cmd += ["-severity", severity]
        # A specific template id (e.g. a CVE) takes precedence over broad tags:
        # a fingerprint-confirmed lead deserves a single-template check.
        if template_id:
            cmd += ["-id", template_id]
        elif tags:
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
            classification = info.get("classification", {}) or {}
            # classification.cve-id may be a list or a single string - normalize,
            # so we never iterate over the characters of a bare CVE string.
            raw_cve = classification.get("cve-id") or []
            cve_ids = [raw_cve] if isinstance(raw_cve, str) else list(raw_cve)
            # nuclei carries the CVSS base score when the template knows one -
            # feed it straight into the report scoring layer.
            cvss_raw = classification.get("cvss-score")
            try:
                cvss = float(cvss_raw) if cvss_raw is not None else None
            except (TypeError, ValueError):
                cvss = None

            if host_name:
                state.upsert_host(host_name)
            state.add_finding(Finding(
                title=title,
                severity=sev,
                host=host_name or None,
                description=info.get("description", "") or "",
                evidence=matched,
                cve=[c.upper() for c in cve_ids],
                cvss=cvss,
                # A nuclei match is a template that ACTUALLY hit against the
                # target - that is proof, not a guess.
                validation="confirmed",
                proof=f"nuclei template {m.get('template-id') or '?'} matched",
            ))
            notes.append(f"[{sev.value}] {title} @ {matched}")
        return notes or ["nuclei: no matches"]


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"
