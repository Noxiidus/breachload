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
    def _ran(self, st, tool, url="http://10.10.10.5:80"):
        from breachload.core.state import ActionRecord
        st.record_action(ActionRecord(phase=Phase.ENUM, tool=tool, command=[tool, url]))

    def test_http_service_gets_httpx_first(self):
        st = _state_with(Phase.ENUM, [Service(port=80, name="http")])
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "httpx" and "10.10.10.5:80" in plan.target

    def test_http_progresses_httpx_then_whatweb_then_ffuf(self):
        st = _state_with(Phase.ENUM, [Service(port=80, name="http")])
        self._ran(st, "httpx")
        assert Planner()._heuristic(st, _tools()).tool == "whatweb"
        self._ran(st, "whatweb")
        assert Planner()._heuristic(st, _tools()).tool == "appfinger"
        self._ran(st, "appfinger")
        assert Planner()._heuristic(st, _tools()).tool == "ffuf"

    def test_smb_service_gets_netexec_then_enum4linux(self):
        from breachload.core.state import ActionRecord
        st = _state_with(Phase.ENUM, [Service(port=445, name="microsoft-ds")])
        assert Planner()._heuristic(st, _tools()).tool == "netexec"
        st.record_action(ActionRecord(phase=Phase.ENUM, tool="netexec",
                                      command=["nxc", "smb", "10.10.10.5"]))
        assert Planner()._heuristic(st, _tools()).tool == "enum4linux-ng"

    def test_vhostfuzz_triggers_for_domain_host(self):
        # A named domain vhost with an HTTP service should get subdomain fuzzing.
        st = EngagementState(name="t", phase=Phase.ENUM)
        host = st.upsert_host("paperwork.htb")
        host.upsert_service(Service(port=80, name="http"))
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "vhostfuzz" and plan.target == "paperwork.htb"

    def test_no_vhostfuzz_for_ip_host(self):
        # An IP has no subdomains — fuzzing must never be proposed for it.
        st = _state_with(Phase.ENUM, [Service(port=80, name="http")])  # host is an IP
        for tool in ("httpx", "whatweb", "appfinger", "ffuf"):
            self._ran(st, tool)
        assert Planner()._heuristic(st, _tools()).action == "phase_complete"

    def test_multiport_web_no_prefix_collision(self):
        # Regression: enumerating :8080 must not mark :80 as done. has_action's
        # trailing-digit guard keeps the two ports distinct.
        st = _state_with(Phase.ENUM, [Service(port=8080, name="http")])
        for tool in ("httpx", "whatweb", "appfinger", "ffuf"):
            self._ran(st, tool, url="http://10.10.10.5:8080")
        st.hosts["10.10.10.5"].upsert_service(Service(port=80, name="http"))
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "httpx" and "10.10.10.5:80" in plan.target


class TestReconDepth:
    def test_full_ports_when_configured(self):
        from breachload.core.config import EngagementConfig
        cfg = EngagementConfig(name="t", full_ports=True)
        plan = Planner(config=cfg)._heuristic(_state_with(Phase.RECON, []), _tools())
        assert plan.tool == "nmap" and plan.args.get("ports") == "-"

    def test_full_ports_implied_by_ctf(self):
        from breachload.core.config import EngagementConfig
        cfg = EngagementConfig(name="t", ctf=True)
        assert cfg.scan_all_ports is True
        plan = Planner(config=cfg)._heuristic(_state_with(Phase.RECON, []), _tools())
        assert plan.args.get("ports") == "-"

    def test_default_recon_stays_top_ports(self):
        plan = Planner()._heuristic(_state_with(Phase.RECON, []), _tools())
        assert plan.tool == "nmap" and not plan.args.get("ports")

    def test_ffuf_gets_extensions_from_config(self):
        from breachload.core.config import EngagementConfig
        cfg = EngagementConfig(name="t", web_extensions="php,txt")
        st = _state_with(Phase.ENUM, [Service(port=80, name="http")])
        p = Planner(config=cfg)
        # advance past httpx + whatweb to the ffuf step
        from breachload.core.state import ActionRecord
        for t in ("httpx", "whatweb", "appfinger"):
            st.record_action(ActionRecord(phase=Phase.ENUM, tool=t,
                                          command=[t, "http://10.10.10.5:80"]))
        plan = p._heuristic(st, _tools())
        assert plan.tool == "ffuf" and plan.args.get("extensions") == "php,txt"


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


class TestHasActionBoundary:
    """A numeric needle must not be a false prefix of a longer number."""

    def _state_with_nmap_on(self, target):
        from breachload.core.state import ActionRecord
        st = EngagementState(name="t")
        st.record_action(ActionRecord(phase=Phase.RECON, tool="nmap",
                                      command=["nmap", "-sV", target]))
        return st

    def test_port_not_a_prefix_of_longer_port(self):
        st = self._state_with_nmap_on("http://10.10.10.5:8080")
        assert st.has_action("nmap", "10.10.10.5:8080")
        assert not st.has_action("nmap", "10.10.10.5:80")

    def test_host_not_a_prefix_of_longer_host(self):
        st = self._state_with_nmap_on("10.10.10.50")
        assert st.has_action("nmap", "10.10.10.50")
        assert not st.has_action("nmap", "10.10.10.5")

    def test_exact_match_still_works(self):
        st = self._state_with_nmap_on("10.10.10.5")
        assert st.has_action("nmap", "10.10.10.5")

    def test_host_not_a_suffix_of_longer_host(self):
        # Leading-digit guard: 10.10.10.5 must not match 210.10.10.5.
        st = self._state_with_nmap_on("210.10.10.5")
        assert st.has_action("nmap", "210.10.10.5")
        assert not st.has_action("nmap", "10.10.10.5")
