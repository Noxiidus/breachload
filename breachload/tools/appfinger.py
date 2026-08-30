"""Application fingerprinting adapter — deep web-app detection.

whatweb/httpx often miss the *application* when the root redirects (e.g. a PBX or
admin panel) or hides its name behind a generic server banner. This adapter fetches
the URL following redirects (`curl -sL`), then matches the title / meta-generator /
body / headers against a curated signature table for the apps breachload has CVEs
and auto-foothold modules for. A hit records a ``webapp: <App> <version>`` note, so
the web-CVE matcher fires and (in auto-exploit mode) the auto-foothold can trigger —
without a human seeding the finding.

Single request per host, read-only (RECON risk).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.httpfetch import fetch_argv
from ..core.state import EngagementState, Service
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult
from .whatweb import _as_url, _split_target


@dataclass
class _Sig:
    app: str
    patterns: list[str]              # any of these (regex, case-insensitive) => match
    version_re: str | None = None    # capture group 1 = version, searched in the body


# Curated to the apps we can act on (have a CVE / foothold module). Ordered so a
# more-specific app wins over a generic one.
_SIGNATURES: list[_Sig] = [
    _Sig("FreePBX", [r"FreePBX Administration", r"freepbx"], r"version=(\d+(?:\.\d+)+)"),
    _Sig("Grafana", [r"<title>Grafana</title>", r'"grafanaBootData"', r"grafana"],
         r"grafana[^0-9]{0,10}(\d+\.\d+\.\d+)"),
    _Sig("WordPress", [r'name="generator" content="WordPress', r"/wp-content/", r"wp-login"],
         r"WordPress (\d+\.\d+(?:\.\d+)?)"),
    _Sig("Joomla", [r"Joomla!", r"com_content", r"/media/jui/"],
         r"Joomla![^0-9]{0,10}(\d+\.\d+)"),
    _Sig("Drupal", [r"X-Generator: Drupal", r"Drupal.settings", r'content="Drupal'],
         r"Drupal (\d+)"),
    _Sig("Jenkins", [r"X-Jenkins:", r"<title>.*Jenkins", r"Dashboard \[Jenkins\]"],
         r"Jenkins[^0-9]{0,6}(\d+\.\d+)"),
    _Sig("GitLab", [r"gitlab", r"GitLab"], r"GitLab (\d+\.\d+)"),
    _Sig("phpMyAdmin", [r"phpMyAdmin", r"pma_"], r"phpMyAdmin (\d+\.\d+\.\d+)"),
    _Sig("Confluence", [r"Confluence", r"confluence-base-url"], None),
    _Sig("Cacti", [r"<title>.*Cacti", r"cacti"], r"Version (\d+\.\d+\.\d+)"),
    _Sig("Nginx UI", [r"nginx-ui", r"0xJacky", r"Nginx UI"], r"(\d+\.\d+\.\d+)"),
    _Sig("Tomcat", [r"Apache Tomcat"], r"Apache Tomcat/(\d+\.\d+\.\d+)"),
    _Sig("Webmin", [r"<title>.*Webmin", r"webmin"], r"Webmin (\d+\.\d+)"),
    _Sig("Metabase", [r"Metabase", r"metabase"], None),
    _Sig("ownCloud", [r"ownCloud", r"owncloud"], None),
    # Expanded to match the widened web-CVE KB.
    _Sig("Nextcloud", [r"Nextcloud", r"data-requesttoken", r"nextcloud"],
         r"Nextcloud[^0-9]{0,10}(\d+\.\d+\.\d+)"),
    _Sig("GLPI", [r"<title>GLPI", r"glpi_", r"content=\"GLPI"], r"GLPI (\d+\.\d+(?:\.\d+)?)"),
    _Sig("pfSense", [r"pfSense", r"__csrf_magic"], r"pfSense[^0-9]{0,10}(\d+\.\d+)"),
    _Sig("Zabbix", [r"<title>.*Zabbix", r"zabbix"], r"Zabbix (\d+\.\d+)"),
    _Sig("Roundcube", [r"Roundcube", r"rcmail", r"roundcube"],
         r"Roundcube[^0-9]{0,10}(\d+\.\d+\.\d+)"),
    _Sig("Zimbra", [r"Zimbra", r"zimbra"], r"Zimbra[^0-9]{0,10}(\d+\.\d+\.\d+)"),
    _Sig("TeamCity", [r"TeamCity", r"tc-header"], r"TeamCity[^0-9]{0,10}(\d+\.\d+)"),
    _Sig("Moodle", [r"Moodle", r"moodle", r"M.cfg"], r"Moodle (\d+\.\d+)"),
    _Sig("Magento", [r"Magento", r"/static/frontend/", r"Mage.Cookies"], None),
    _Sig("Craft CMS", [r"Craft CMS", r"craftcms", r"X-Powered-By: Craft CMS"],
         r"Craft CMS (\d+\.\d+)"),
    _Sig("ColdFusion", [r"ColdFusion", r"/CFIDE/", r"cfml"], None),
    _Sig("Citrix", [r"Citrix", r"/vpn/index.html", r"NetScaler"], None),
    _Sig("Apache OFBiz", [r"OFBiz", r"ofbiz", r"/webtools/control"], None),
    _Sig("WSO2", [r"WSO2", r"wso2", r"carbon"], None),
    _Sig("FortiOS", [r"/remote/login", r"FortiGate", r"fortinet"], None),
    _Sig("Laravel", [r"laravel_session", r"Laravel", r"/_ignition/"], None),
    _Sig("Apache NiFi", [r"<title>NiFi</title>", r"/nifi/images/nifi16\.ico", r"/nifi-api/"],
         None),
]


@dataclass
class AppFingerAdapter(ToolAdapter):
    name: str = "appfinger"
    binary: str = "curl"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["http", "fingerprint"]

    def build_command(self, target: str, **kwargs) -> list[str]:
        self._target = target
        # -L follows redirects (root -> /admin login is how many apps hide), -i
        # includes headers (some apps only reveal via X-Generator/X-Jenkins). The
        # resilient policy adds retries and a 128 KB Range cap so a large/slow body
        # (classic MTU stall) can't hang the fingerprint — the head is enough.
        return fetch_argv(_as_url(target), follow=True, include_headers=True,
                          max_bytes=131072, timeout=20, retries=2)

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        body = result.stdout or ""
        if not body.strip():
            return [f"appfinger: no response (exit {result.exit_code})"]

        host, port, scheme = _split_target(target) if target else ("", 80, "http")
        notes: list[str] = []
        for sig in _SIGNATURES:
            if not any(re.search(p, body, re.IGNORECASE) for p in sig.patterns):
                continue
            version = ""
            if sig.version_re:
                m = re.search(sig.version_re, body, re.IGNORECASE)
                if m:
                    version = m.group(1)
            note = f"webapp: {sig.app}" + (f" {version}" if version else "")
            if host:
                h = state.upsert_host(host)
                svc = h.services.get(f"{port}/tcp") or Service(port=port, name=scheme,
                                                               state="open")
                if note not in svc.notes:
                    svc.notes.append(note)
                h.upsert_service(svc)
            notes.append(f"appfinger: {sig.app}" + (f" {version}" if version else ""))
        return notes or ["appfinger: no known application matched"]
