"""End-to-end: the orchestrator walks recon → enumeration → vuln automatically,
using the heuristic planner and adapters whose execution is stubbed with canned
tool output. Proves the "guide from recon to findings" flow and that real parsers
populate state along the way.
"""

import asyncio
import types
from pathlib import Path

from breachload.core.config import EngagementConfig
from breachload.core.llm import Planner
from breachload.core.orchestrator import Orchestrator
from breachload.core.state import EngagementState, Phase, Severity
from breachload.safety.audit import AuditLog
from breachload.safety.scope import Scope
from breachload.safety.validator import Validator
from breachload.tools.base import ToolResult
from breachload.tools.registry import allowed_binaries, default_registry

HOST = "10.10.10.5"

CANNED = {
    "nmap": ("<?xml version=\"1.0\"?><nmaprun><host>"
             f"<address addr=\"{HOST}\" addrtype=\"ipv4\"/><ports>"
             "<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>"
             "<service name=\"http\" product=\"Apache httpd\" version=\"2.4.49\"/></port>"
             "<port protocol=\"tcp\" portid=\"445\"><state state=\"open\"/>"
             "<service name=\"microsoft-ds\"/></port>"
             "</ports></host></nmaprun>"),
    "whatweb": f'[{{"target":"http://{HOST}","http_status":200,'
               '"plugins":{"Apache":{"version":["2.4.49"]},"PHP":{"version":["7.4"]}}}]',
    "ffuf": '{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":10,'
            f'"url":"http://{HOST}:80/admin","host":"{HOST}"}}]}}',
    "enum4linux-ng": f'{{"target":{{"host":"{HOST}","workgroup":"WG"}},'
                     '"sessions":{"Null session":true},'
                     '"shares":{"public":{"access":["READ","OK"],"type":"Disk"}},'
                     '"users":{"1000":{"username":"bob"}}}',
    "nuclei": f'{{"template-id":"CVE-2021-41773","info":{{"name":"Path Traversal",'
              '"severity":"critical","classification":{"cve-id":["cve-2021-41773"]}},'
              f'"host":"http://{HOST}:80","matched-at":"http://{HOST}:80/x"}}',
}


def _stub_registry():
    reg = default_registry()
    for adapter in reg.values():
        async def _run(self, command, timeout=600.0, _name=adapter.name):
            return ToolResult(0, CANNED.get(_name, ""), "", 0.01)
        adapter.run = types.MethodType(_run, adapter)
    return reg


def _orchestrator(tmp_path: Path, analyzer=None):
    cfg = EngagementConfig(name="e2e", targets=[f"{HOST}/32"])
    state = EngagementState(name="e2e")
    state.upsert_host(HOST)
    reg = _stub_registry()
    scope = Scope.from_config(cfg.targets)
    validator = Validator(scope, allowed_binaries(reg), cfg.auto_risk)
    audit = AuditLog(tmp_path / "audit.jsonl")
    planner = Planner()
    planner._client = None  # force the offline heuristic — env-independent test
    events: list[tuple[str, str]] = []
    orch = Orchestrator(cfg, state, reg, validator, planner, audit,
                        tmp_path / "state.json",
                        on_event=lambda ev, msg: events.append((ev, msg)),
                        analyzer=analyzer)
    return orch, state, events


def test_full_chain_populates_state(tmp_path):
    orch, state, events = _orchestrator(tmp_path)
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))

    # Services discovered in recon.
    host = state.hosts[HOST]
    assert "80/tcp" in host.services and "445/tcp" in host.services

    # Every phase's tools ran, in order, exactly once each.
    tools_run = [a.tool for a in state.history]
    assert tools_run == ["nmap", "whatweb", "ffuf", "enum4linux-ng", "nuclei"]

    # Findings from ffuf (paths), enum4linux (null session), nuclei (critical CVE).
    titles = " ".join(f.title.lower() for f in state.findings)
    assert "paths discovered" in titles
    assert "null session" in titles
    assert any(f.severity == Severity.CRITICAL for f in state.findings)
    assert any("CVE-2021-41773" in f.cve for f in state.findings)

    # Credentials (usernames) collected during enumeration.
    assert any(c.username == "bob" for c in state.credentials)

    # Ended in the vuln phase, entered all three.
    entered = [msg for ev, msg in events if ev == "phase"]
    assert any("recon" in m for m in entered)
    assert any("enumeration" in m for m in entered)
    assert any("vuln" in m for m in entered)


def test_analyzer_runs_in_chain(tmp_path):
    from breachload.analysis.analyzer import Analyzer
    orch, state, events = _orchestrator(tmp_path, analyzer=Analyzer.default())
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))

    # Version-based CVE from the analyzer, in addition to nuclei's own match.
    with_cve = [f for f in state.findings if "CVE-2021-41773" in f.cve]
    assert len(with_cve) >= 2
    assert any(ev == "finding" for ev, _ in events)


def test_resume_does_not_repeat_actions(tmp_path):
    orch, state, _ = _orchestrator(tmp_path)
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    count_before = len(state.history)
    # Running again from a completed state should add no new actions.
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    assert len(state.history) == count_before
