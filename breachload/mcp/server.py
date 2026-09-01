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


def _tool_next_step(args: dict) -> dict:
    """Given a state.json blob, return the heuristic planner's next action.

    The agent hands us a serialized EngagementState (as JSON), we run the
    deterministic planner over it, and return the rendered next step. No I/O,
    no target contact - just the decision.
    """
    from ..core.llm import Planner
    from ..core.state import EngagementState
    from ..tools.registry import default_registry
    try:
        state = EngagementState.model_validate_json(args.get("state", "{}"))
    except Exception as exc:  # noqa: BLE001
        return _content(f"invalid state: {exc}")
    tools = [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
             for a in default_registry(load_plugins=False).values()]
    plan = Planner()._heuristic(state, tools)
    return _content(json.dumps({
        "action": plan.action, "tool": plan.tool, "target": plan.target,
        "args": plan.args, "rationale": plan.rationale,
    }, indent=2, default=str))


def _tool_suggest(args: dict) -> dict:
    """Render the rule-based SuggestionEngine plan for a state - no API key needed."""
    from ..analysis.suggest import SuggestionEngine
    from ..core.state import EngagementState
    try:
        state = EngagementState.model_validate_json(args.get("state", "{}"))
    except Exception as exc:  # noqa: BLE001
        return _content(f"invalid state: {exc}")
    lhost = args.get("lhost", "LHOST")
    lport = int(args.get("lport", 4444) or 4444)
    plan = SuggestionEngine().suggest(state, lhost=lhost, lport=lport)
    return _content(json.dumps([{
        "title": s.title, "why": s.why, "actions": s.actions,
    } for s in plan], indent=2))


def _tool_render_report(args: dict) -> dict:
    """Render the Markdown or HTML report for a state - one-shot deliverable."""
    from ..core.state import EngagementState
    from ..report.engine import render_markdown
    from ..report.html import render_html
    try:
        state = EngagementState.model_validate_json(args.get("state", "{}"))
    except Exception as exc:  # noqa: BLE001
        return _content(f"invalid state: {exc}")
    fmt = (args.get("format") or "markdown").lower()
    if fmt == "html":
        return _content(render_html(state))
    return _content(render_markdown(state))


def _tool_secret_scan(args: dict) -> dict:
    """Scan arbitrary text for secrets (AWS keys, JWT, DB URIs, ...)."""
    from ..analysis.secretscan import scan_secrets
    findings, creds = scan_secrets(args.get("text", ""))
    return _content(json.dumps({
        "findings": [{"title": f.title, "evidence": f.evidence[:200]}
                     for f in findings],
        "credentials": [{"kind": c.kind, "secret": (c.secret or "")[:120],
                         "source": c.source} for c in creds],
    }, indent=2))


def _tool_default_creds(args: dict) -> dict:
    """Emit the default-credential sweep argvs for a state."""
    from ..analysis.defaultcreds import sweep_commands
    from ..core.state import EngagementState
    try:
        state = EngagementState.model_validate_json(args.get("state", "{}"))
    except Exception as exc:  # noqa: BLE001
        return _content(f"invalid state: {exc}")
    return _content(json.dumps(
        [{"host": h, "technique": t, "argv": a} for h, t, a in sweep_commands(state)],
        indent=2))


def _tool_privesc_classes(args: dict) -> dict:
    """Run generalized Linux privesc-class detectors over a shell-enum blob."""
    from ..analysis.privesc_classes import find_all as pc
    from ..analysis.writable_root_paths import find_writable_root_exec
    text = args.get("enum", "")
    findings = pc(text) + find_writable_root_exec(text)
    return _content(json.dumps([{
        "title": f.title, "severity": f.severity.value, "exploit": f.exploit,
    } for f in findings], indent=2) or "no privesc-class hits")


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
    "next_step": (
        "Deterministic planner: given a serialized EngagementState, return the "
        "next action (tool/target/rationale).",
        {"type": "object", "properties": {"state": {"type": "string"}},
         "required": ["state"]},
        _tool_next_step),
    "suggest": (
        "Rule-based SuggestionEngine plan over a serialized state - no API key.",
        {"type": "object", "properties": {
            "state": {"type": "string"}, "lhost": {"type": "string"},
            "lport": {"type": "integer"}}, "required": ["state"]},
        _tool_suggest),
    "render_report": (
        "Render the Markdown or HTML report for a serialized state.",
        {"type": "object", "properties": {
            "state": {"type": "string"},
            "format": {"type": "string", "enum": ["markdown", "html"]}},
         "required": ["state"]},
        _tool_render_report),
    "secret_scan": (
        "Scan arbitrary text for secrets (cloud keys, JWT, DB URIs, passwords).",
        {"type": "object", "properties": {"text": {"type": "string"}},
         "required": ["text"]},
        _tool_secret_scan),
    "default_creds": (
        "Default-credential sweep argvs for every service in a serialized state.",
        {"type": "object", "properties": {"state": {"type": "string"}},
         "required": ["state"]},
        _tool_default_creds),
    "privesc_classes": (
        "Run generalized Linux privesc-class detectors on a shell-enum blob "
        "(writable-root-path, PATH hijack, writable systemd unit, writable SUID).",
        {"type": "object", "properties": {"enum": {"type": "string"}},
         "required": ["enum"]},
        _tool_privesc_classes),
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
