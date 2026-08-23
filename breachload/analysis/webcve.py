"""Web-application version -> CVE mapping with guided exploitation.

The banner-based `CveMatcher` only inspects a service's product/name, which
carries the *server* (Apache, nginx) but not the *web application* running on it.
Web-app tech (WordPress, Grafana, Gitea, Nginx UI, ...) is fingerprinted by
whatweb/httpx and lands in the service **notes** instead — so a fingerprinted
"Nginx UI 2.3.2" was previously never mapped to a CVE. This matcher closes that
gap: it scans the whole fingerprint (product, name, banner, notes) for a known
web app, optionally range-matches its version, and attaches a ready-to-run,
confirm-gated exploitation hint to the finding.

Two match modes, per KB entry:
- with a version `range`: fire only when a version is discoverable in the
  fingerprint and falls in range (a strong lead);
- with an empty `range`: fire on the app token alone as a lead to verify — many
  web-app CVEs affect a wide range or need a manual version check anyway.

Fully offline. The KB (`data/webapp_kb.json`) is curated and HTB-relevant;
grow it with the same schema.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from ..core.state import EngagementState, Finding, Host, Service, Severity
from .cve import satisfies

_HTTP_PORTS = (80, 443, 8080, 8443, 8000, 3000)
# A version token sitting next to an app name: "WordPress 6.2", "Grafana/8.3.0",
# "nginx-ui:2.3.2", "Joomla[4.2.0]". Captured as the first \d+.\d+... run.
_VER_RE = re.compile(r"[\s/:_\[\-]v?(\d+(?:\.\d+)+)")


@dataclass
class WebCveEntry:
    match: list[str]
    range: str
    cve: str
    severity: str
    name: str
    exploit: str = ""
    note: str = ""


def _haystack(svc: Service) -> str:
    parts = [svc.product or "", svc.name or "", svc.banner or "", *svc.notes]
    return " ".join(parts).lower()


def _find_version(haystack: str, token: str) -> str | None:
    """A version string appearing just after `token` in the fingerprint text."""
    idx = haystack.find(token)
    if idx < 0:
        return None
    window = haystack[idx + len(token): idx + len(token) + 24]
    m = _VER_RE.match(window) or _VER_RE.search(window)
    return m.group(1) if m else None


def _web_port(host: Host, svc: Service) -> int:
    """A concrete port for the exploit template: this service's port if it looks
    like HTTP, else the host's first HTTP port, else the service port."""
    if svc.port in _HTTP_PORTS or "http" in (svc.name or "").lower():
        return svc.port
    for p in _HTTP_PORTS:
        if any(s.port == p for s in host.services.values()):
            return p
    return svc.port


class WebCveMatcher:
    def __init__(self, entries: list[WebCveEntry]) -> None:
        self.entries = entries

    @classmethod
    def default(cls) -> WebCveMatcher:
        """Bundled web-app KB, plus any extra feed in ``BREACHLOAD_WEBAPP_KB``."""
        raw = json.loads(
            resources.files("breachload.data").joinpath("webapp_kb.json").read_text(encoding="utf-8")
        )
        entries = cls._parse(raw)
        extra = os.environ.get("BREACHLOAD_WEBAPP_KB")
        if extra and Path(extra).is_file():
            entries += cls._parse(json.loads(Path(extra).read_text(encoding="utf-8")))
        return cls(entries)

    @staticmethod
    def _parse(raw: dict) -> list[WebCveEntry]:
        return [
            WebCveEntry(
                match=[t.lower() for t in e["match"]],
                range=e.get("range", ""), cve=e["cve"],
                severity=e["severity"], name=e["name"],
                exploit=e.get("exploit", ""), note=e.get("note", ""),
            )
            for e in raw.get("entries", [])
        ]

    def findings_for(self, state: EngagementState) -> list[Finding]:
        out: list[Finding] = []
        for host in state.hosts.values():
            for svc in host.services.values():
                haystack = _haystack(svc)
                if not haystack.strip():
                    continue
                for e in self.entries:
                    if not all(tok in haystack for tok in e.match):
                        continue
                    version = _find_version(haystack, e.match[0])
                    if e.range:
                        if not version or not satisfies(version, e.range):
                            continue
                    out.append(self._finding(host, svc, e, version))
        return out

    def _finding(self, host: Host, svc: Service, e: WebCveEntry, version: str | None) -> Finding:
        port = _web_port(host, svc)
        exploit = e.exploit.replace("{TARGET}", host.address).replace("{PORT}", str(port))
        ver_txt = f" {version}" if version else ""
        verify = ("" if e.range else " Version not confirmed from the fingerprint - "
                  "VERIFY it is in the vulnerable range.")
        desc = (f"{e.name}: the fingerprint on {host.address}:{port} indicates "
                f"{e.match[0]}{ver_txt}, affected by {e.cve}.{verify} "
                f"{e.note}".strip())
        return Finding(
            title=f"{e.name} ({e.cve})",
            severity=Severity(e.severity),
            host=host.address,
            service_key=svc.key,
            description=desc,
            cve=[e.cve],
            exploit=exploit,
            remediation="Update the application to a patched version.",
        )
