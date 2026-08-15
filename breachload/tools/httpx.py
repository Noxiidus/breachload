"""httpx adapter — HTTP service fingerprint enrichment.

Runs projectdiscovery's httpx over a web service and folds its structured probe
(status code, page title, web server, detected technologies) into the matching
HTTP service. Complements whatweb with cleaner, machine-readable output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.state import EngagementState, Service
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class HttpxAdapter(ToolAdapter):
    name: str = "httpx"
    binary: str = "httpx"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "fingerprint"]

    def build_command(self, target: str, **kwargs) -> list[str]:
        url = target if "://" in target else f"http://{target}"
        # -json: machine-readable; the probes enrich each result line.
        return ["httpx", "-silent", "-json", "-title", "-tech-detect",
                "-status-code", "-web-server", "-u", url]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        entries = _json_lines(result.stdout)
        if not entries:
            # No JSON often means the `httpx` on PATH is the Python HTTP client,
            # not ProjectDiscovery's prober (a common name collision) — name it so
            # the operator doesn't chase a phantom failure.
            return [f"httpx: no parseable JSON (exit {result.exit_code}) — ensure the "
                    "`httpx` on PATH is ProjectDiscovery's prober, not the python client"]

        notes: list[str] = []
        for entry in entries:
            host_name, port, scheme = _endpoint(entry)
            if not host_name:
                continue
            host = state.upsert_host(host_name)
            svc = Service(port=port, name=scheme, state="open")

            server = entry.get("webserver")
            if server:
                svc.product = server
            title = entry.get("title")
            if title:
                svc.notes.append(f"httpx title: {title[:120]}")
            techs = entry.get("tech") or []
            if techs:
                svc.notes.append("httpx tech: " + ", ".join(techs[:20]))
            host.upsert_service(svc)

            status = entry.get("status_code", "")
            notes.append(
                f"{host_name} {port}/tcp {scheme} [{status}] {server or ''} "
                f"\"{title or ''}\" ({len(techs)} techs)".strip()
            )
        return notes or ["httpx: nothing detected"]


def _json_lines(stdout: str) -> list[dict]:
    out: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _endpoint(entry: dict) -> tuple[str, int, str]:
    scheme = entry.get("scheme") or "http"
    host = entry.get("host") or ""
    port = entry.get("port")
    if not host or not port:
        parsed = urlparse(entry.get("url") or entry.get("input") or "")
        host = host or parsed.hostname or ""
        scheme = parsed.scheme or scheme
        port = port or parsed.port or (443 if scheme == "https" else 80)
    return host, int(port), scheme
