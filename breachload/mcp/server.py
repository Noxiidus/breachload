"""A minimal, dependency-free MCP server exposing breachload to any LLM agent.

Rather than pull in the MCP SDK, this speaks the Model Context Protocol directly
over stdio (newline-delimited JSON-RPC 2.0): `initialize`, `tools/list`,
`tools/call`. It is deliberately scoped to breachload's SAFE, DETERMINISTIC surface
- the parsers, the planner, the knowledge base, the report renderer. It never fires
a tool at a target and never bypasses the scope/validator layers; an agent that
wants to *run* something still goes through the CLI with its confirm/scope gates.

That division is the whole point: the intelligence (any agent - including the one
reading this) drives, while breachload contributes the trustworthy, reviewed pieces
(fingerprint->CVE, AD chain composition, hash identification, roast parsing, the
report). Think of it as giving a coding agent a security co-processor it can call.

Handlers are pure functions over JSON: trivially unit-testable without any socket.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

PROTOCOL_VERSION = "2024-11-05"


def _content(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


# --- tool implementations (pure: dict in -> dict out) -----------------------

def _tool_parse_nmap(args: dict) -> dict:
    from ..core.state import EngagementState
    from ..tools.base import ToolResult
    from ..tools.nmap import NmapAdapter
    st = EngagementState(name="mcp")
    a = NmapAdapter()
    # NmapAdapter.parse reads the XML from stdout, not output_file.
    a.parse(ToolResult(exit_code=0, stdout=args.get("xml", ""), stderr="",
                       duration_s=0.0), st)
    return _content(json.dumps(st.model_dump(), default=str)[:60000])


def _tool_fingerprint_cve(args: dict) -> dict:
    """Map a fingerprint string (product/version/notes) to known-CVE leads."""
    from ..analysis.webcve import WebCveMatcher
    from ..core.state import EngagementState, Service
    st = EngagementState(name="mcp")
    h = st.upsert_host(args.get("host", "target"))
    h.upsert_service(Service(port=int(args.get("port", 80)), name="http",
                             product=args.get("product"),
                             notes=[args.get("fingerprint", "")]))
    findings = WebCveMatcher.default().findings_for(st)
    if not findings:
        return _content("no known-CVE leads for that fingerprint")
    return _content(json.dumps([{"title": f.title, "cve": f.cve, "severity":
                                 f.severity.value, "exploit": f.exploit}
                                for f in findings], indent=2))


def _tool_ad_killchain(args: dict) -> dict:
    """Order a list of AD finding titles into a ranked path to Domain Admin."""
    from ..analysis.adchain import plan_ad_chain, render_chain
    from ..core.state import Finding, Severity
    findings = [Finding(title=t, severity=Severity.HIGH)
                for t in args.get("finding_titles", [])]
    chain = plan_ad_chain(findings, have_creds=bool(args.get("have_creds")))
    return _content("\n".join(render_chain(chain, have_creds=bool(args.get("have_creds")))))


def _tool_parse_roast(args: dict) -> dict:
    """Parse impacket AS-REP/Kerberoast output into findings + hashcat modes."""
    from ..analysis.kerberos import creds_from_roast, parse_roast
    text = args.get("output", "")
    findings = parse_roast(text)
    creds = creds_from_roast(text)
    return _content(json.dumps({
        "findings": [f.title for f in findings],
        "hashes": [{"user": c.username, "hash": (c.secret or "")[:80]} for c in creds],
    }, indent=2))


def _tool_identify_hash(args: dict) -> dict:
    from ..analysis.hashcrack import crack_commands, identify
    h = args.get("hash", "")
    cands = identify(h)
    return _content(json.dumps({
        "types": [{"name": c.name, "hashcat_mode": c.hashcat_mode} for c in cands],
        "commands": crack_commands(h, args.get("wordlist",
                                               "/usr/share/wordlists/rockyou.txt")),
    }, indent=2))


def _tool_pivot_plan(args: dict) -> dict:
    from ..analysis.pivot import pivot_plan, render_pivot
    opts = pivot_plan(args.get("lhost", "LHOST"), via_host=args.get("via", "EDGE"),
                      subnet=args.get("subnet"), ssh_user=args.get("ssh_user"))
    return _content("\n".join(render_pivot(opts)))


def _tool_explain(args: dict) -> dict:
    from ..analysis.glossary import lookup
    t = lookup(args.get("term", ""))
    if t is None:
        return _content("unknown term")
    return _content(f"# {t.title}\n\nWhat: {t.what}\n\nWhy it matters: {t.why}\n\n"
                    f"In breachload: {t.breachload}\n\nLearn: {t.learn}")


def _tool_gtfobins(args: dict) -> dict:
    from ..analysis.gtfobins import lookup
    entry = lookup(args.get("binary", ""))
    return _content(json.dumps(entry, indent=2) if entry else "no GTFOBins entry")


TOOLS: dict[str, tuple[str, dict, Callable[[dict], dict]]] = {
    "fingerprint_to_cve": (
        "Map a web-app fingerprint (product/version/banner) to known-CVE leads with "
        "ready exploit commands.",
        {"type": "object", "properties": {
            "fingerprint": {"type": "string"}, "product": {"type": "string"},
            "host": {"type": "string"}, "port": {"type": "integer"}},
         "required": ["fingerprint"]},
        _tool_fingerprint_cve),
    "ad_killchain": (
        "Order AD finding titles (BloodHound/ADCS/roasting) into a ranked path to "
        "Domain Admin with the next command per step.",
        {"type": "object", "properties": {
            "finding_titles": {"type": "array", "items": {"type": "string"}},
            "have_creds": {"type": "boolean"}}, "required": ["finding_titles"]},
        _tool_ad_killchain),
    "parse_roast": (
        "Parse impacket AS-REP/Kerberoast output into findings and crackable hashes.",
        {"type": "object", "properties": {"output": {"type": "string"}},
         "required": ["output"]},
        _tool_parse_roast),
    "identify_hash": (
        "Identify a password hash and return hashcat mode + crack commands.",
        {"type": "object", "properties": {"hash": {"type": "string"},
                                          "wordlist": {"type": "string"}},
         "required": ["hash"]},
        _tool_identify_hash),
    "pivot_plan": (
        "Generate tunnelling commands (sshuttle/chisel/ligolo/ssh) to reach an "
        "internal subnet via a compromised edge host.",
        {"type": "object", "properties": {
            "lhost": {"type": "string"}, "via": {"type": "string"},
            "subnet": {"type": "string"}, "ssh_user": {"type": "string"}},
         "required": ["via"]},
        _tool_pivot_plan),
    "explain_term": (
        "Explain a security term (ssti, kerberoast, esc1, ...).",
        {"type": "object", "properties": {"term": {"type": "string"}},
         "required": ["term"]},
        _tool_explain),
    "gtfobins": (
        "Look up GTFOBins escalation techniques for a SUID/sudo binary.",
        {"type": "object", "properties": {"binary": {"type": "string"}},
         "required": ["binary"]},
        _tool_gtfobins),
    "parse_nmap_xml": (
        "Parse nmap XML output into structured hosts/services/findings.",
        {"type": "object", "properties": {"xml": {"type": "string"}},
         "required": ["xml"]},
        _tool_parse_nmap),
}


def handle(request: dict) -> dict | None:
    """Handle one JSON-RPC request, returning a response dict (or None for a notify)."""
    method = request.get("method")
    rid = request.get("id")

    def ok(result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def err(code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    if method == "initialize":
        return ok({"protocolVersion": PROTOCOL_VERSION,
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "breachload", "version": _version()}})
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return ok({"tools": [
            {"name": name, "description": desc, "inputSchema": schema}
            for name, (desc, schema, _fn) in TOOLS.items()]})
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        entry = TOOLS.get(name)
        if not entry:
            return err(-32602, f"unknown tool: {name}")
        try:
            return ok(entry[2](params.get("arguments") or {}))
        except Exception as exc:  # noqa: BLE001 - report tool errors as content, not crash
            return ok({"content": [{"type": "text", "text": f"error: {exc}"}],
                       "isError": True})
    if rid is None:
        return None
    return err(-32601, f"method not found: {method}")


def _version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "0"


def serve(stdin=None, stdout=None) -> None:  # pragma: no cover - I/O loop
    """Run the stdio JSON-RPC loop (newline-delimited)."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(request)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
