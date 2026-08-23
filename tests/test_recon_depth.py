"""Recon depth: UDP nmap pass and recursive ffuf, threaded from the config."""

from breachload.core.config import EngagementConfig
from breachload.core.llm import Planner
from breachload.core.state import ActionRecord, EngagementState, Phase, Service
from breachload.tools.ffuf import FfufAdapter
from breachload.tools.nmap import NmapAdapter
from breachload.tools.registry import default_registry


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestNmapUdp:
    def test_udp_command(self):
        cmd = NmapAdapter().build_command("10.10.10.5", udp=True, top_ports=25)
        assert "-sU" in cmd and "--top-ports" in cmd and "25" in cmd
        assert "-p-" not in cmd


class TestFfufRecursion:
    def test_recursion_flags(self):
        cmd = FfufAdapter().build_command("http://10.10.10.5", recursion=True, recursion_depth=2)
        assert "-recursion" in cmd
        assert cmd[cmd.index("-recursion-depth") + 1] == "2"

    def test_no_recursion_by_default(self):
        assert "-recursion" not in FfufAdapter().build_command("http://10.10.10.5")


class TestPlannerUdp:
    def _recon_state(self):
        st = EngagementState(name="t", phase=Phase.RECON)
        st.upsert_host("10.10.10.5").upsert_service(Service(port=80, name="http"))
        return st

    def test_udp_pass_after_tcp(self):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"], udp_scan=True)
        plan = Planner(config=cfg)._heuristic(self._recon_state(), _tools())
        assert plan.tool == "nmap" and plan.args.get("udp") is True

    def test_udp_runs_once(self):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"], udp_scan=True)
        st = self._recon_state()
        st.record_action(ActionRecord(
            phase=Phase.RECON, tool="nmap",
            command=["nmap", "-oX", "-", "-Pn", "-sV", "-sU", "--top-ports", "20", "10.10.10.5"]))
        plan = Planner(config=cfg)._heuristic(st, _tools())
        assert plan.action == "phase_complete"

    def test_no_udp_without_config(self):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"], udp_scan=False)
        plan = Planner(config=cfg)._heuristic(self._recon_state(), _tools())
        assert plan.action == "phase_complete"


class TestPlannerFfufRecursion:
    def test_recursion_threaded_from_config(self):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"],
                               ffuf_recursion=True, recursion_depth=3)
        st = EngagementState(name="t", phase=Phase.ENUM)
        st.upsert_host("10.10.10.5").upsert_service(Service(port=80, name="http"))
        # Drive past httpx/whatweb/appfinger so the planner reaches the ffuf step.
        for tool in ("httpx", "whatweb", "appfinger"):
            st.record_action(ActionRecord(phase=Phase.ENUM, tool=tool,
                                          command=[tool, "http://10.10.10.5:80"]))
        plan = Planner(config=cfg)._heuristic(st, _tools())
        assert plan.tool == "ffuf"
        assert plan.args.get("recursion") is True and plan.args.get("recursion_depth") == 3
