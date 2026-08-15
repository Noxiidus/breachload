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
    # ffuf writes valid JSON only to a real file: `-s` (needed to silence its
    # noisy live UI) also suppresses `-o /dev/stdout`, so the two together yield
    # plain text, not JSON. Route JSON through a tool-managed OUTFILE instead.
    # Suffix is "" (the marker IS the file): ffuf's `-o PATH` writes to exactly
    # PATH — unlike tools whose flag appends an extension to the base path.
    output_file_suffix: str | None = ""

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
        # -s silences the live UI; JSON goes to the OUTFILE (not stdout, which -s
        # would corrupt). -ac auto-calibrates against random paths so a host that
        # blanket-redirects every request (e.g. an IP that 301s to its vhost)
        # doesn't report the whole wordlist as "found".
        return [
            "ffuf", "-w", wordlist, "-u", url,
            "-mc", match_codes, "-ac", "-s", "-of", "json", "-o", "{OUTFILE}",
        ]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        # Prefer the JSON file; fall back to stdout so unit tests (and any future
        # stdout-based invocation) keep working.
        text = (result.output_file or result.stdout or "").strip()
        if not text:
            return [f"ffuf: no output (exit {result.exit_code})"]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ["ffuf: could not parse JSON output"]

        results = data.get("results") or []
        if not results:
            return ["ffuf: no paths discovered"]

        # Group by (host, port) — derived from each result URL — so notes attach
        # to the exact web service, not all lumped onto port 80.
        by_endpoint: dict[tuple[str, int], list[str]] = {}
        notes: list[str] = []
        for r in results:
            parsed = urlparse(r.get("url", ""))
            host_name = parsed.hostname or ""
            if not host_name:
                continue
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            status = r.get("status")
            path = parsed.path or "/"
            by_endpoint.setdefault((host_name, port), []).append(f"{path} [{status}]")
            notes.append(f"{host_name}:{port} {path} [{status}] ({r.get('length')}b)")

        for (host_name, port), paths in by_endpoint.items():
            host = state.upsert_host(host_name)
            svc = host.services.get(f"{port}/tcp")
            if svc is not None:
                svc.notes.append(f"ffuf: {len(paths)} paths ({', '.join(paths[:10])})")
            state.add_finding(Finding(
                title=f"{len(paths)} paths discovered on {host_name}:{port}",
                severity=Severity.INFO,
                host=host_name,
                service_key=f"{port}/tcp",
                description="Content discovery via ffuf.",
                evidence="\n".join(paths[:50]),
            ))
        return notes


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"
