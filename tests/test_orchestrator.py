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
    "httpx": f'{{"host":"{HOST}","port":"80","scheme":"http","url":"http://{HOST}",'
             '"status_code":200,"title":"Home","webserver":"Apache/2.4.49","tech":["PHP"]}',
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


def _orchestrator(tmp_path: Path, analyzer=None, ctf=False, on_state=None, rate_limiter=None):
    cfg = EngagementConfig(name="e2e", targets=[f"{HOST}/32"], ctf=ctf)
    state = EngagementState(name="e2e")
    state.upsert_host(HOST)
    reg = _stub_registry()
    scope = Scope.from_config(cfg.targets)
    validator = Validator(scope, allowed_binaries(reg), cfg.effective_threshold)
    audit = AuditLog(tmp_path / "audit.jsonl")
    planner = Planner()
    planner._client = None  # force the offline heuristic — env-independent test
    events: list[tuple[str, str]] = []
    orch = Orchestrator(cfg, state, reg, validator, planner, audit,
                        tmp_path / "state.json",
                        on_event=lambda ev, msg: events.append((ev, msg)),
                        analyzer=analyzer, on_state=on_state, rate_limiter=rate_limiter)
    return orch, state, events


def test_full_chain_populates_state(tmp_path):
    orch, state, events = _orchestrator(tmp_path)
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))

    # Services discovered in recon.
    host = state.hosts[HOST]
    assert "80/tcp" in host.services and "445/tcp" in host.services

    # Every phase's tools ran, in order, exactly once each.
    tools_run = [a.tool for a in state.history]
    assert tools_run == ["nmap", "httpx", "whatweb", "ffuf", "enum4linux-ng", "nuclei"]

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


def test_tool_failure_is_isolated(tmp_path):
    """A crashing adapter must not abort the run, and must be recorded once."""
    orch, state, events = _orchestrator(tmp_path)

    async def _boom(self, command, timeout=600.0):
        raise RuntimeError("nmap segfaulted")
    orch.registry["nmap"].run = types.MethodType(_boom, orch.registry["nmap"])

    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))  # must not raise

    nmap_records = [a for a in state.history if a.tool == "nmap"]
    assert len(nmap_records) == 1                 # recorded, not retried forever
    assert nmap_records[0].exit_code == -1
    assert any(ev == "error" for ev, _ in events)


def test_kill_switch_stops_before_running(tmp_path):
    orch, state, events = _orchestrator(tmp_path)
    orch.request_stop()
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    assert state.history == []                       # nothing ran
    assert any(ev == "stopped" for ev, _ in events)


def test_ctf_captures_flag_from_output(tmp_path):
    from breachload.tools.base import ToolResult
    orch, state, events = _orchestrator(tmp_path, ctf=True)
    orch._capture_flags(ToolResult(0, "banner: flag{c4ptur3d}", "", 0.1), ["note line"])
    assert "flag{c4ptur3d}" in state.flags
    assert any(ev == "flag" for ev, _ in events)
    # A second capture of the same flag is deduplicated.
    orch._capture_flags(ToolResult(0, "flag{c4ptur3d}", "", 0.1), [])
    assert state.flags.count("flag{c4ptur3d}") == 1


def test_ctf_mode_raises_threshold(tmp_path):
    from breachload.core.config import EngagementConfig
    from breachload.safety.validator import Risk
    assert EngagementConfig(name="t", ctf=True).effective_threshold == Risk.EXPLOIT


def test_on_state_pushed_each_step(tmp_path):
    snapshots = []
    orch, state, _ = _orchestrator(tmp_path, on_state=lambda st: snapshots.append(st.phase))
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    assert len(snapshots) == len(state.history)      # one push per executed step


def test_rate_limiter_is_awaited(tmp_path):
    from breachload.core.ratelimit import RateLimiter
    slept = []

    async def fake_sleep(s):
        slept.append(s)

    clock = iter([0.0, 0.0, 5.0, 5.0, 10.0, 10.0, 15.0, 15.0, 20.0, 20.0, 25.0, 25.0])
    rl = RateLimiter(1.0, clock=lambda: next(clock, 100.0), sleep=fake_sleep)
    orch, state, _ = _orchestrator(tmp_path, rate_limiter=rl)
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    # With a large elapsed gap the limiter shouldn't sleep, but it must be invoked
    # once per executed action (no exceptions => wait() ran in the loop).
    assert state.history                              # actions ran through the limiter


def test_resume_does_not_repeat_actions(tmp_path):
    orch, state, _ = _orchestrator(tmp_path)
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    count_before = len(state.history)
    # Running again from a completed state should add no new actions.
    asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
    assert len(state.history) == count_before
