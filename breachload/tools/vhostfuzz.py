"""Virtual-host / subdomain fuzzing adapter (ffuf with a fuzzed Host header).

Many web boxes serve their real application on a name-based virtual host rather
than the default site. Given a known domain (e.g. ``paperwork.htb``), this fuzzes
``Host: FUZZ.<domain>`` against the in-scope server and records every vhost that
answers differently from the baseline, so the planner can enumerate it next.

All requests go to the in-scope ``-u`` host (the same server); only the Host
header changes. Discovered names still need to resolve (usually via /etc/hosts)
and be in scope before they are enumerated — both enforced elsewhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

_DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


@dataclass
class VhostFuzzAdapter(ToolAdapter):
    name: str = "vhostfuzz"
    binary: str = "ffuf"
    risk: Risk = Risk.ACTIVE
    # Same OUTFILE convention as the ffuf adapter: -o writes exactly the path.
    output_file_suffix: str | None = ""

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "vhost-discovery"]

    def build_command(
        self,
        target: str,
        *,
        wordlist: str = _DEFAULT_WORDLIST,
    ) -> list[str]:
        domain = urlparse(target).hostname or target
        url = target if "://" in target else f"http://{domain}/"
        # -ac auto-calibrates against random vhosts, filtering the default site's
        # blanket response so only genuinely distinct vhosts are reported. -mc all
        # keeps every status; calibration does the filtering.
        return [
            "ffuf", "-w", wordlist, "-u", url,
            "-H", f"Host: FUZZ.{domain}",
            "-mc", "all", "-ac", "-s", "-of", "json", "-o", "{OUTFILE}",
        ]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        text = (result.output_file or result.stdout or "").strip()
        if not text:
            return [f"vhostfuzz: no output (exit {result.exit_code})"]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ["vhostfuzz: could not parse JSON output"]

        results = data.get("results") or []
        if not results:
            return ["vhostfuzz: no virtual hosts discovered"]

        notes: list[str] = []
        for r in results:
            fuzz = (r.get("input") or {}).get("FUZZ")
            base = urlparse(r.get("url", "")).hostname or ""
            if not fuzz or not base:
                continue
            vhost = f"{fuzz}.{base}"
            status, length = r.get("status"), r.get("length")
            host = state.upsert_host(vhost)
            host.upsert_service(Service(port=80, name="http", state="open"))
            state.add_finding(Finding(
                title=f"Virtual host discovered: {vhost}",
                severity=Severity.INFO,
                host=vhost,
                service_key="80/tcp",
                description=(
                    f"{vhost} responds on the target ([{status}], {length}b). Add it "
                    f"to /etc/hosts (and scope) to enumerate it."
                ),
                evidence=f"Host: {vhost} -> [{status}] {length}b",
            ))
            notes.append(f"vhost {vhost} [{status}] ({length}b)")
        return notes or ["vhostfuzz: no virtual hosts discovered"]
