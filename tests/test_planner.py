"""Heuristic planner: capability- and state-driven action selection per phase."""

from breachload.core.llm import Planner
from breachload.core.state import EngagementState, Phase, Service
from breachload.tools.registry import default_registry


def _tools() -> list[dict]:
    return [
        {"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
        for a in default_registry().values()
    ]


def _state_with(phase: Phase, services: list[Service]) -> EngagementState:
    st = EngagementState(name="t", phase=phase)
    host = st.upsert_host("10.10.10.5")
    for svc in services:
        host.upsert_service(svc)
    return st


class TestReconPhase:
    def test_scans_unscanned_host(self):
        st = _state_with(Phase.RECON, [])
        plan = Planner()._heuristic(st, _tools())
        assert plan.action == "run" and plan.tool == "nmap"

    def test_completes_when_all_scanned(self):
        st = _state_with(Phase.RECON, [Service(port=80, name="http")])
        plan = Planner()._heuristic(st, _tools())
        assert plan.action == "phase_complete"


class TestEnumPhase:
    def test_http_service_gets_whatweb_first(self):
        st = _state_with(Phase.ENUM, [Service(port=80, name="http")])
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "whatweb" and "10.10.10.5:80" in plan.target

    def test_smb_service_gets_enum4linux(self):
        st = _state_with(Phase.ENUM, [Service(port=445, name="microsoft-ds")])
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "enum4linux-ng"

    def test_skips_already_run_tools(self):
        from breachload.core.state import ActionRecord
        st = _state_with(Phase.ENUM, [Service(port=80, name="http")])
        st.record_action(ActionRecord(phase=Phase.ENUM, tool="whatweb",
                                      command=["whatweb", "http://10.10.10.5:80"]))
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "ffuf"  # moves on to the next tool


class TestLlmFallback:
    def test_api_error_falls_back_to_heuristic(self):
        class _FakeClient:
            class messages:
                @staticmethod
                def create(**kwargs):
                    raise RuntimeError("api down")

        planner = Planner()
        planner._client = _FakeClient()
        plan = planner.next_action(_state_with(Phase.RECON, []), _tools())
        assert plan.tool == "nmap"   # fell back to the deterministic heuristic


class TestVulnPhase:
    def test_http_service_gets_nuclei(self):
        st = _state_with(Phase.VULN, [Service(port=8080, name="http-proxy")])
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "nuclei" and "8080" in plan.target

    def test_no_http_completes(self):
        st = _state_with(Phase.VULN, [Service(port=445, name="microsoft-ds")])
        plan = Planner()._heuristic(st, _tools())
        assert plan.action == "phase_complete"
