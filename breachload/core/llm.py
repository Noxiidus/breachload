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
from dataclasses import dataclass

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
            for host in state.hosts.values():
                if not host.services and not state.has_action("nmap", host.address):
                    args = {"ports": "-"} if full else {}
                    why = ("No services known yet; full-port service scan (-p-)."
                           if full else "No services known yet; run a service scan.")
                    return Plan("run", "nmap", host.address, args, why)
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
                        if "ffuf" in names and not state.has_action("ffuf", key):
                            exts = (self.config.web_extensions if self.config else "") or ""
                            args = {"extensions": exts} if exts else {}
                            return Plan("run", "ffuf", url, args,
                                        "Discover hidden content on the web service.")
                    if _is_smb(svc):
                        if "netexec" in names and not state.has_action("netexec", host.address):
                            return Plan("run", "netexec", host.address, {},
                                        "SMB/AD fingerprint (host, domain, signing) via netexec.")
                        if "enum4linux-ng" in names \
                                and not state.has_action("enum4linux-ng", host.address):
                            return Plan("run", "enum4linux-ng", host.address, {},
                                        "Enumerate SMB shares, users, and null sessions.")
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
            return Plan("phase_complete", rationale="Enumeration exhausted for known services.")

        if state.phase == Phase.VULN:
            for host in state.hosts.values():
                for svc in host.services.values():
                    key = f"{host.address}:{svc.port}"
                    if _is_http(svc) and "nuclei" in names and not state.has_action("nuclei", key):
                        return Plan("run", "nuclei", _svc_url(host.address, svc), {},
                                    "Scan the web service for known vulnerabilities.")
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


def _is_nfs(svc) -> bool:
    return (svc.name or "").lower() in ("nfs", "nfs_acl", "rpcbind", "mountd") \
        or svc.port in (2049, 111)


def _is_ftp(svc) -> bool:
    return (svc.name or "").lower() in ("ftp", "ftp-data") or svc.port == 21


def _is_redis(svc) -> bool:
    return (svc.name or "").lower() == "redis" or svc.port == 6379


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


def _svc_url(host: str, svc) -> str:
    https = (svc.name or "").lower() in ("https", "ssl/http") or svc.port in _HTTPS_PORTS
    scheme = "https" if https else "http"
    return f"{scheme}://{host}:{svc.port}"
