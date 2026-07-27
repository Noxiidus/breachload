"""ffuf adapter — HTTP content discovery (directory/file brute-forcing).

Active by risk class: it hammers the target with requests. Discovered paths are
recorded as notes on the HTTP service and surfaced as INFO findings so they show
up in the report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.state import EngagementState, Finding, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

_DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


@dataclass
class FfufAdapter(ToolAdapter):
    name: str = "ffuf"
    binary: str = "ffuf"
    risk: Risk = Risk.ACTIVE

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "content-discovery"]

    def build_command(
        self,
        target: str,
        *,
        wordlist: str = _DEFAULT_WORDLIST,
        match_codes: str = "200,204,301,302,307,401,403",
    ) -> list[str]:
        url = target if "FUZZ" in target else f"{_as_url(target).rstrip('/')}/FUZZ"
        # -s silent, JSON to stdout so parse() gets structured results.
        return [
            "ffuf", "-w", wordlist, "-u", url,
            "-mc", match_codes, "-s", "-of", "json", "-o", "/dev/stdout",
        ]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        text = result.stdout.strip()
        if not text:
            return [f"ffuf: no output (exit {result.exit_code})"]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ["ffuf: could not parse JSON output"]

        results = data.get("results") or []
        if not results:
            return ["ffuf: no paths discovered"]

        # Group by host so notes attach to the right service.
        by_host: dict[str, list[str]] = {}
        notes: list[str] = []
        for r in results:
            url = r.get("url", "")
            parsed = urlparse(url)
            host_name = parsed.hostname or ""
            if not host_name:
                continue
            status = r.get("status")
            path = parsed.path or "/"
            by_host.setdefault(host_name, []).append(f"{path} [{status}]")
            notes.append(f"{host_name} {path} [{status}] ({r.get('length')}b)")

        for host_name, paths in by_host.items():
            host = state.upsert_host(host_name)
            port = urlparse(_as_url(host_name)).port or 80
            svc = host.services.get(f"{port}/tcp")
            if svc is not None:
                svc.notes.append(f"ffuf: {len(paths)} paths ({', '.join(paths[:10])})")
            state.add_finding(Finding(
                title=f"{len(paths)} paths discovered on {host_name}",
                severity=Severity.INFO,
                host=host_name,
                description="Content discovery via ffuf.",
                evidence="\n".join(paths[:50]),
            ))
        return notes


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"
