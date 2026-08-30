"""LLM reasoning layer (Claude).

The model's job is narrow and well-defined: given the structured state summary
and the list of available tools, decide the next action and explain why. It does
NOT parse output and it does NOT get to bypass the safety layer — whatever it
proposes is validated in code before running.

The client is optional: if no API key is configured, breachload falls back to a
deterministic heuristic planner so the whole pipeline still runs offline.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass

from ..exploit.autofire import probe_for
from .state import EngagementState, Phase

SYSTEM_PROMPT = """You are the planning core of breachload, an autonomous pentest \
assistant operating strictly inside an authorized engagement scope.

You are given a structured summary of what is currently known about the target(s) \
and a list of available tools. Decide the single best next action.

Rules:
- Propose exactly one tool invocation, or signal that the current phase is complete.
- You never invent hosts, ports, or services — reason only from the provided state.
- You explain your reasoning concisely: what you expect to learn and why now.
- Scope and command safety are enforced by a separate deterministic layer; do not \
worry about it, just propose the technically best next step.

Respond ONLY with JSON:
{"action": "run|phase_complete", "tool": "<name>", "target": "<host>", \
"args": {...}, "rationale": "<one or two sentences>"}"""


@dataclass
class Plan:
    action: str                  # "run" | "phase_complete"
    tool: str | None = None
    target: str | None = None
    args: dict | None = None
    rationale: str = ""


class Planner:
    """Wraps Claude, with a heuristic fallback when no key is present."""

    def __init__(self, model: str = "claude-opus-5", config=None) -> None:
        self.model = model
        # Engagement config drives recon depth (full ports) and web fuzzing
        # extensions; optional so the planner still works standalone/in tests.
        self.config = config
        self._client = None
        key = os.environ.get("ANTHROPIC_API_KEY")
        if key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=key)
            except ImportError:
                self._client = None

    @property
    def online(self) -> bool:
        return self._client is not None

    def next_action(self, state: EngagementState, tools: list[dict]) -> Plan:
        if self._client is None:
            return self._heuristic(state, tools)
        user = json.dumps({
            "state": state.summary(),
            "phase": state.phase,
            "tools": tools,
        }, indent=2)
        # Any API failure (network, rate limit, auth) falls back to the
        # deterministic heuristic so the engagement keeps moving.
        try:
            msg = self._client.messages.create(
                model=self.model,
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user}],
            )
            text = msg.content[0].text.strip()
        except Exception:  # noqa: BLE001 — resilience: never let the planner crash the run
            return self._heuristic(state, tools)
        return self._parse_plan(text, state, tools)

    def _parse_plan(self, text: str, state: EngagementState, tools: list[dict]) -> Plan:
        try:
            start, end = text.index("{"), text.rindex("}") + 1
            data = json.loads(text[start:end])
            return Plan(
                action=data.get("action", "phase_complete"),
                tool=data.get("tool"),
                target=data.get("target"),
                args=data.get("args") or {},
                rationale=data.get("rationale", ""),
            )
        except (ValueError, json.JSONDecodeError):
            return self._heuristic(state, tools)

    def _heuristic(self, state: EngagementState, tools: list[dict]) -> Plan:
        """Zero-LLM planner: capability- and state-driven, drives recon→enum→vuln.

        Deterministic enough to walk an engagement end-to-end without the API,
        and a clear reference for what the LLM planner is expected to do.
        """
        names = {t["name"] for t in tools}

        if state.phase == Phase.RECON:
            full = bool(self.config and self.config.scan_all_ports)
            udp = bool(self.config and self.config.udp_scan)
            for host in state.hosts.values():
                if not host.services and not state.has_action("nmap", host.address):
                    args = {"ports": "-"} if full else {}
                    why = ("No services known yet; full-port service scan (-p-)."
                           if full else "No services known yet; run a service scan.")
                    return Plan("run", "nmap", host.address, args, why)
            if udp:
                # After the TCP sweep, a top-ports UDP pass surfaces SNMP/DNS/TFTP/IKE.
                for host in state.hosts.values():
                    if not _udp_scanned(state, host.address):
                        return Plan("run", "nmap", host.address, {"udp": True},
                                    "TCP sweep done; top-ports UDP pass (SNMP/DNS/TFTP).")
            return Plan("phase_complete", rationale="All hosts have been scanned.")

        if state.phase == Phase.ENUM:
            for host in state.hosts.values():
                if "vhostfuzz" in names and _is_fuzzable_domain(host.address) \
                        and _has_http(host) and not state.has_action("vhostfuzz", host.address):
                    return Plan("run", "vhostfuzz", host.address, {},
                                "Fuzz for name-based virtual hosts / subdomains.")
                for svc in host.services.values():
                    key = f"{host.address}:{svc.port}"
                    if _is_http(svc):
                        url = _svc_url(host.address, svc)
                        if "httpx" in names and not state.has_action("httpx", key):
                            return Plan("run", "httpx", url, {},
                                        "Fingerprint the web service (httpx).")
                        if "whatweb" in names and not state.has_action("whatweb", key):
                            return Plan("run", "whatweb", url, {},
                                        "Fingerprint the web service.")
                        if "appfinger" in names and not state.has_action("appfinger", key):
                            return Plan("run", "appfinger", url, {},
                                        "Deep app fingerprint (follows redirects to the "
                                        "real app / admin panel).")
                        if "ffuf" in names and not state.has_action("ffuf", key):
                            ffuf_args: dict[str, object] = {}
                            exts = (self.config.web_extensions if self.config else "") or ""
                            if exts:
                                ffuf_args["extensions"] = exts
                            if self.config and self.config.ffuf_recursion:
                                ffuf_args["recursion"] = True
                                ffuf_args["recursion_depth"] = self.config.recursion_depth
                            return Plan("run", "ffuf", url, ffuf_args,
                                        "Discover hidden content on the web service.")
                    if _is_smb(svc):
                        if "netexec" in names and not state.has_action("netexec", host.address):
                            return Plan("run", "netexec", host.address, {},
                                        "SMB/AD fingerprint (host, domain, signing) via netexec.")
                        if "enum4linux-ng" in names \
                                and not state.has_action("enum4linux-ng", host.address):
                            return Plan("run", "enum4linux-ng", host.address, {},
                                        "Enumerate SMB shares, users, and null sessions.")
                    if _is_dns(svc) and "dns" in names and not state.has_action("dns", key):
                        return Plan("run", "dns", host.address, {"port": svc.port},
                                    "Attempt a DNS zone transfer (AXFR) to dump the zone.")
                    if _is_snmp(svc) and "snmp" in names and not state.has_action("snmp", key):
                        return Plan("run", "snmp", host.address, {"port": svc.port},
                                    "Read the SNMP tree with community 'public'.")
                    if _is_nfs(svc) and "nfs" in names \
                            and not state.has_action("nfs", host.address):
                        return Plan("run", "nfs", host.address, {},
                                    "List NFS exports (showmount).")
                    if _is_ftp(svc) and "ftp" in names and not state.has_action("ftp", key):
                        return Plan("run", "ftp", host.address, {"port": svc.port},
                                    "Check for anonymous FTP login.")
                    if _is_redis(svc) and "redis" in names and not state.has_action("redis", key):
                        return Plan("run", "redis", host.address, {"port": svc.port},
                                    "Probe Redis for unauthenticated access.")
                    if _is_smtp(svc) and "smtp" in names and not state.has_action("smtp", key):
                        return Plan("run", "smtp", host.address, {"port": svc.port},
                                    "Enumerate SMTP usernames via VRFY.")
                    if _is_mysql(svc) and "mysql" in names and not state.has_action("mysql", key):
                        return Plan("run", "mysql", host.address, {"port": svc.port},
                                    "Test MySQL for a blank/weak root login.")
                    if _is_postgres(svc) and "postgres" in names \
                            and not state.has_action("postgres", key):
                        return Plan("run", "postgres", host.address, {"port": svc.port},
                                    "Test PostgreSQL for a trust/blank login.")
                    if _is_mssql(svc) and "mssql" in names and not state.has_action("mssql", key):
                        return Plan("run", "mssql", host.address, {"port": svc.port},
                                    "Test MSSQL for a blank sa login.")
                    if _is_ldap(svc) and "ldap" in names and not state.has_action("ldap", key):
                        return Plan("run", "ldap", host.address, {"port": svc.port},
                                    "Try an anonymous LDAP bind and read naming contexts.")
                    if _is_rpc(svc) and "rpc" in names \
                            and not state.has_action("rpc", host.address):
                        return Plan("run", "rpc", host.address, {},
                                    "Dump the RPC portmapper (rpcinfo).")
                    if _is_rsync(svc) and "rsync" in names and not state.has_action("rsync", key):
                        return Plan("run", "rsync", host.address, {"port": svc.port},
                                    "List exposed rsync modules.")
                    if _is_mongo(svc) and "mongodb" in names \
                            and not state.has_action("mongodb", key):
                        return Plan("run", "mongodb", host.address, {"port": svc.port},
                                    "Test MongoDB for unauthenticated access.")
            return Plan("phase_complete", rationale="Enumeration exhausted for known services.")

        if state.phase == Phase.EXPLOIT:
            # Autonomous EXPLOIT actions are limited to the curated, READ-ONLY probes
            # (curl argv, no shell, no code execution). RCE/write exploits are never
            # auto-fired — they stay surfaced as guided commands. Reached only via the
            # auto-exploit walk (or an explicit --phase exploitation, still risk-gated).
            if "exploit-probe" in names:
                for f in state.findings:
                    for cve in f.cve:
                        if probe_for(cve) and f.host:
                            port = _port_from_key(f.service_key) or 80
                            if not _probe_fired(state, cve, f.host, port):
                                return Plan("run", "exploit-probe", f.host,
                                            {"cve": cve, "port": port},
                                            f"Auto-fire the read-only {cve} disclosure probe.")
            return Plan("phase_complete", rationale="No auto-fireable exploit probes remain.")

        if state.phase == Phase.VULN:
            for host in state.hosts.values():
                for svc in host.services.values():
                    key = f"{host.address}:{svc.port}"
                    if _is_http(svc) and "nuclei" in names and not state.has_action("nuclei", key):
                        # Auto-select nuclei templates for the detected stack — a
                        # targeted, faster scan than the full template set. If the
                        # fingerprint already names a CVE, confirm that exact one.
                        cve_ids = _service_cve_ids(state, host, svc)
                        tags = _nuclei_tags(svc)
                        if cve_ids:
                            args = {"template_id": ",".join(cve_ids)}
                            why = (f"Confirm the fingerprinted lead with nuclei "
                                   f"(-id {args['template_id']}).")
                        elif tags:
                            args = {"tags": tags}
                            why = f"Scan the web service with nuclei (tags: {tags})."
                        else:
                            args = {}
                            why = "Scan the web service for known vulnerabilities."
                        return Plan("run", "nuclei", _svc_url(host.address, svc), args, why)
            return Plan("phase_complete", rationale="Vulnerability scan complete.")

        return Plan("phase_complete", rationale="No heuristic for this phase yet.")


_HTTP_NAMES = ("http", "https", "http-proxy", "ssl/http", "http-alt")
_HTTPS_PORTS = (443, 8443)
_SMB_NAMES = ("microsoft-ds", "netbios-ssn", "smb")
_SMB_PORTS = (139, 445)


def _is_http(svc) -> bool:
    return (svc.name or "").lower() in _HTTP_NAMES or svc.port in (80, 443, 8080, 8443, 8000)


def _is_snmp(svc) -> bool:
    return (svc.name or "").lower().startswith("snmp") or svc.port == 161


def _is_dns(svc) -> bool:
    return (svc.name or "").lower().startswith("domain") \
        or (svc.name or "").lower() == "dns" or svc.port == 53


def _is_nfs(svc) -> bool:
    # Port 111 / rpcbind is the RPC adapter's (portmapper dump); NFS proper is 2049.
    return (svc.name or "").lower() in ("nfs", "nfs_acl", "mountd") or svc.port == 2049


def _is_ftp(svc) -> bool:
    return (svc.name or "").lower() in ("ftp", "ftp-data") or svc.port == 21


def _is_redis(svc) -> bool:
    return (svc.name or "").lower() == "redis" or svc.port == 6379


def _is_smtp(svc) -> bool:
    return (svc.name or "").lower() in ("smtp", "submission") or svc.port in (25, 587, 465)


def _is_mysql(svc) -> bool:
    return (svc.name or "").lower() in ("mysql", "mariadb") or svc.port == 3306


def _is_postgres(svc) -> bool:
    return (svc.name or "").lower() in ("postgresql", "postgres") or svc.port == 5432


def _is_mssql(svc) -> bool:
    return (svc.name or "").lower() in ("ms-sql-s", "mssql", "ms-sql") or svc.port == 1433


def _is_ldap(svc) -> bool:
    return (svc.name or "").lower() in ("ldap", "ldapssl", "globalcatldap") \
        or svc.port in (389, 636, 3268)


def _is_rpc(svc) -> bool:
    return (svc.name or "").lower() in ("rpcbind", "portmapper", "sunrpc") or svc.port == 111


def _is_rsync(svc) -> bool:
    return (svc.name or "").lower() == "rsync" or svc.port == 873


def _is_mongo(svc) -> bool:
    return (svc.name or "").lower() in ("mongodb", "mongod") or svc.port == 27017


# Fingerprint token -> nuclei tag. Scanned against the service product/name/notes so
# a detected stack picks the matching template set instead of running everything.
_NUCLEI_TAG_MAP = {
    "wordpress": "wordpress", "joomla": "joomla", "drupal": "drupal", "magento": "magento",
    "apache": "apache", "nginx": "nginx", "iis": "iis", "tomcat": "tomcat",
    "jboss": "jboss", "weblogic": "weblogic", "jenkins": "jenkins", "gitlab": "gitlab",
    "gitea": "gitea", "grafana": "grafana", "kibana": "kibana", "jira": "jira",
    "confluence": "confluence", "phpmyadmin": "phpmyadmin", "spring": "springboot",
    "struts": "struts", "laravel": "laravel", "wso2": "wso2", "zabbix": "zabbix",
    "cacti": "cacti", "solr": "solr", "coldfusion": "coldfusion", "citrix": "citrix",
    # Expanded stack coverage (matches the webapp CVE KB).
    "freepbx": "freepbx", "moodle": "moodle", "nextcloud": "nextcloud",
    "owncloud": "owncloud", "pfsense": "pfsense", "fortinet": "fortinet",
    "fortios": "fortinet", "fortigate": "fortinet", "glpi": "glpi",
    "roundcube": "roundcube", "zimbra": "zimbra", "ofbiz": "ofbiz", "wso2 ": "wso2",
    "teamcity": "teamcity", "craftcms": "craftcms", "craft cms": "craftcms",
    "metabase": "metabase", "webmin": "webmin", "nagios": "nagios", "sharepoint": "sharepoint",
    "exchange": "exchange", "outlook web": "exchange", "vcenter": "vmware", "vmware": "vmware",
    "openfire": "openfire", "rocketchat": "rocketchat", "rocket.chat": "rocketchat",
    "wordpress plugin": "wpplugin", "elasticsearch": "elasticsearch", "kafka": "kafka",
    "keycloak": "keycloak", "airflow": "airflow", "django": "django", "flask": "werkzeug",
    "werkzeug": "werkzeug", "symfony": "symfony", "prometheus": "prometheus",
    "harbor": "harbor", "minio": "minio", "consul": "consul", "traefik": "traefik",
    "ivanti": "ivanti", "sonicwall": "sonicwall", "papercut": "papercut", "phpinfo": "phpinfo",
}

# nuclei can target one template by CVE id (`-id CVE-...`). We pull ids out of the
# fingerprint notes so a KB-confirmed vuln gets a one-template confirmation run.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _nuclei_tags(svc) -> str:
    """Comma-joined nuclei tags for a service's detected technologies (dedup, ordered)."""
    haystack = " ".join([svc.product or "", svc.name or "", *svc.notes]).lower()
    tags: list[str] = []
    for token, tag in _NUCLEI_TAG_MAP.items():
        if token in haystack and tag not in tags:
            tags.append(tag)
    return ",".join(tags)


def _nuclei_cve_ids(svc) -> list[str]:
    """CVE ids named in a service's notes, upper-cased and de-duplicated in order.

    When appfinger/webcve has already pinned a CVE to the fingerprint, feeding that
    id to `nuclei -id` confirms it with a single template instead of the whole tag
    set -- fast, low-noise validation of the exact lead.
    """
    haystack = " ".join([svc.product or "", svc.name or "", *svc.notes])
    ids: list[str] = []
    for m in _CVE_RE.findall(haystack):
        cid = m.upper()
        if cid not in ids:
            ids.append(cid)
    return ids


def _service_cve_ids(state, host, svc) -> list[str]:
    """CVE ids for a service from BOTH its fingerprint notes and any finding that
    the web-CVE matcher already attached to it — so a KB lead (which lands as a
    Finding, not a note) still routes nuclei to the exact template.
    """
    ids = _nuclei_cve_ids(svc)
    for f in state.findings:
        if f.host == host.address and (f.service_key or "") in ("", svc.key):
            for cid in f.cve or []:
                cid = cid.upper()
                if _CVE_RE.fullmatch(cid) and cid not in ids:
                    ids.append(cid)
    return ids


def _has_http(host) -> bool:
    return any(_is_http(svc) for svc in host.services.values())


def _is_fuzzable_domain(address: str) -> bool:
    """A name-based vhost apex worth subdomain-fuzzing: a hostname (not an IP)
    with a single label + TLD, e.g. `paperwork.htb`. Skips IPs and names that are
    already subdomains, so we don't fuzz `FUZZ.www.example.com`."""
    try:
        ipaddress.ip_address(address)
        return False                       # an IP has no subdomains to fuzz
    except ValueError:
        return address.count(".") == 1 and " " not in address


def _is_smb(svc) -> bool:
    return (svc.name or "").lower() in _SMB_NAMES or svc.port in _SMB_PORTS


def _port_from_key(service_key: str | None) -> int | None:
    """The port from a 'port/proto' service key (e.g. '3000/tcp' -> 3000)."""
    if not service_key:
        return None
    head = service_key.split("/", 1)[0]
    return int(head) if head.isdigit() else None


def _probe_fired(state, cve: str, host: str, port: int) -> bool:
    """True once the exploit-probe for this (cve, host, port) has run — the adapter
    records a 'Exploit probe fired: <cve> on <host>:<port>' finding."""
    title = f"Exploit probe fired: {cve} on {host}:{port}"
    return any(f.title == title for f in state.findings)


def _udp_scanned(state, address: str) -> bool:
    """True once a UDP nmap pass (-sU) has been run against `address` — so the
    RECON planner asks for it exactly once even when it finds no UDP services."""
    for a in state.history:
        if a.tool == "nmap" and "-sU" in a.command and address in a.command:
            return True
    return False


def _svc_url(host: str, svc) -> str:
    https = (svc.name or "").lower() in ("https", "ssl/http") or svc.port in _HTTPS_PORTS
    scheme = "https" if https else "http"
    from .netutil import host_url
    return host_url(host, svc.port, scheme)
