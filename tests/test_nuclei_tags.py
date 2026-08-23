"""nuclei auto-tagging from the detected web stack."""

from breachload.core.llm import Planner, _nuclei_tags
from breachload.core.state import ActionRecord, EngagementState, Phase, Service
from breachload.tools.registry import default_registry


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestNucleiTags:
    def test_maps_detected_tech(self):
        svc = Service(port=80, name="http", product="Apache",
                      notes=["whatweb: WordPress, MetaGenerator", "webapp: WordPress 6.2"])
        tags = _nuclei_tags(svc)
        assert "wordpress" in tags and "apache" in tags

    def test_empty_without_known_tech(self):
        assert _nuclei_tags(Service(port=80, name="http")) == ""

    def test_planner_passes_tags(self):
        st = EngagementState(name="t", phase=Phase.VULN)
        st.upsert_host("10.10.10.9").upsert_service(
            Service(port=80, name="http", notes=["whatweb: Grafana"]))
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "nuclei" and "grafana" in plan.args.get("tags", "")

    def test_planner_no_tags_when_unknown(self):
        st = EngagementState(name="t", phase=Phase.VULN)
        st.upsert_host("10.10.10.9").upsert_service(Service(port=80, name="http"))
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "nuclei" and plan.args.get("tags") is None

    def test_tags_reach_the_command(self):
        st = EngagementState(name="t", phase=Phase.VULN)
        st.upsert_host("10.10.10.9").upsert_service(
            Service(port=80, name="http", notes=["whatweb: Jenkins"]))
        # once nuclei has run, the phase completes (no re-propose loop)
        st.record_action(ActionRecord(phase=Phase.VULN, tool="nuclei",
                                      command=["nuclei", "-u", "http://10.10.10.9:80"]))
        assert Planner()._heuristic(st, _tools()).action == "phase_complete"
