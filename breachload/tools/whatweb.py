"""whatweb adapter — HTTP fingerprinting.

Runs whatweb with JSON logging and folds detected technologies into the matching
HTTP service. Parsing prefers whatweb's JSON output over its coloured text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.state import EngagementState, Service
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

# whatweb plugins that carry a server product/version worth promoting.
_SERVER_PLUGINS = ("HTTPServer", "Apache", "nginx", "Microsoft-IIS", "LiteSpeed")


@dataclass
class WhatWebAdapter(ToolAdapter):
    name: str = "whatweb"
    binary: str = "whatweb"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "fingerprint"]

    def build_command(self, target: str, *, aggression: int = 1) -> list[str]:
        url = _as_url(target)
        # --log-json=- streams JSON to stdout; -a sets aggression (1 = passive).
        return ["whatweb", "--no-errors", f"-a{aggression}", "--log-json=-", url]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        entries = _load_json_entries(result.stdout)
        if not entries:
            return [f"whatweb: no parseable JSON (exit {result.exit_code})"]

        notes: list[str] = []
        for entry in entries:
            target = entry.get("target", "")
            host_name, port, scheme = _split_target(target)
            if not host_name:
                continue
            host = state.upsert_host(host_name)
            svc = Service(port=port, name=scheme, state="open")

            plugins = entry.get("plugins", {}) or {}
            product = _server_product(plugins)
            if product:
                svc.product = product
            techs = sorted(k for k in plugins if k not in ("Country", "IP", "HTTPServer"))
            if techs:
                svc.notes.append("whatweb: " + ", ".join(techs[:20]))
            status = entry.get("http_status")
            host.upsert_service(svc)
            notes.append(
                f"{host_name} {port}/tcp {scheme} [{status}] {product or ''} "
                f"({len(techs)} techs)".strip()
            )
        return notes or ["whatweb: nothing detected"]


def _server_product(plugins: dict) -> str | None:
    for name in _SERVER_PLUGINS:
        info = plugins.get(name)
        if not info:
            continue
        versions = info.get("version") or []
        strings = info.get("string") or []
        label = name if name != "HTTPServer" else ""
        detail = (strings or versions)
        if detail:
            return f"{label} {detail[0]}".strip()
        return label or name
    return None


def _load_json_entries(stdout: str) -> list[dict]:
    text = stdout.strip()
    if not text:
        return []
    # whatweb emits either a JSON array or newline-delimited objects.
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    entries: list[dict] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"


def _split_target(target: str) -> tuple[str, int, str]:
    parsed = urlparse(_as_url(target))
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    return host, port, scheme
