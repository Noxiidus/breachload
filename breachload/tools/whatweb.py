"""whatweb adapter — HTTP fingerprinting.

Runs whatweb with JSON logging and folds detected technologies into the matching
HTTP service. Parsing prefers whatweb's JSON output over its coloured text.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.state import EngagementState, Finding, Service, Severity
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
        # Bounded open/read timeouts so a slow or streaming root (a homepage that
        # long-polls or never closes the body) can't stall enumeration.
        return ["whatweb", "--no-errors", f"-a{aggression}",
                "--open-timeout=10", "--read-timeout=20", "--log-json=-", url]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        entries = _load_json_entries(result.stdout)
        if not entries:
            # Exit 0 with no JSON means whatweb connected but got nothing usable —
            # typically a root that hangs/streams. Say so instead of a bare miss.
            if result.exit_code == 0:
                return ["whatweb: connected but no data (root may hang or stream; "
                        "try a specific path)"]
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
            # Surface any versioned application (WordPress 6.2, Grafana 8.3.0) as a
            # parseable note so the web-app CVE matcher can range-match it. whatweb
            # carries these under the plugin's "version" list.
            for app_note in _app_versions(plugins):
                svc.notes.append(app_note)
            status = entry.get("http_status")
            host.upsert_service(svc)
            notes.append(
                f"{host_name} {port}/tcp {scheme} [{status}] {product or ''} "
                f"({len(techs)} techs)".strip()
            )
            redirect = _record_redirect(plugins, host_name, port, scheme, state)
            if redirect:
                notes.append(redirect)
        return notes or ["whatweb: nothing detected"]


# Plugins that only mark generic HTTP facts, not an application worth version-mapping.
_NON_APP_PLUGINS = ("Country", "IP", "HTTPServer", "RedirectLocation", "Title",
                    "Cookies", "HttpOnly", "UncommonHeaders", "Via-Proxy",
                    "X-Frame-Options", "X-Powered-By", "Strict-Transport-Security")


def _app_versions(plugins: dict) -> list[str]:
    """`webapp: <Name> <version>` notes for every plugin carrying a version."""
    out: list[str] = []
    for name, info in plugins.items():
        if name in _NON_APP_PLUGINS or not isinstance(info, dict):
            continue
        versions = info.get("version") or []
        for ver in versions[:2]:
            if ver and str(ver).strip():
                out.append(f"webapp: {name} {str(ver).strip()}")
    return out


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


def _redirect_location(plugins: dict) -> str | None:
    strings = (plugins.get("RedirectLocation") or {}).get("string") or []
    return strings[0] if strings else None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _record_redirect(
    plugins: dict, from_host: str, from_port: int, scheme: str, state: EngagementState
) -> str | None:
    """A 301/302 to a *named* virtual host is how many web boxes hide their real
    app. Record the target host + its HTTP service so the planner enumerates it
    next, and flag that the name must resolve (usually via /etc/hosts)."""
    loc = _redirect_location(plugins)
    if not loc:
        return None
    parsed = urlparse(loc)
    rhost = parsed.hostname or ""
    # Ignore same-host and bare-IP redirects — neither reveals a new vhost.
    if not rhost or rhost == from_host or _is_ip(rhost):
        return None
    rscheme = parsed.scheme or "http"
    rport = parsed.port or (443 if rscheme == "https" else 80)
    rh = state.upsert_host(rhost)
    rh.upsert_service(Service(port=rport, name=rscheme, state="open"))
    state.add_finding(Finding(
        title=f"HTTP redirect reveals virtual host {rhost}",
        severity=Severity.INFO,
        host=from_host,
        service_key=f"{from_port}/tcp",
        description=(
            f"{scheme}://{from_host}:{from_port} redirects to {loc}. Enumeration "
            f"will pivot to {rhost}; the name must resolve to the target — add it "
            f"to /etc/hosts (e.g. '<target-ip> {rhost}') if it does not already."
        ),
        evidence=loc,
    ))
    return f"redirect -> vhost {rhost} (queued for enumeration; ensure /etc/hosts maps it)"


def _as_url(target: str) -> str:
    return target if "://" in target else f"http://{target}"


def _split_target(target: str) -> tuple[str, int, str]:
    parsed = urlparse(_as_url(target))
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    return host, port, scheme
