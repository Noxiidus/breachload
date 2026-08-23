"""Deep web-app fingerprinting adapter."""

from breachload.analysis.webcve import WebCveMatcher
from breachload.core.llm import Planner
from breachload.core.state import ActionRecord, EngagementState, Phase, Service
from breachload.tools.appfinger import AppFingerAdapter
from breachload.tools.base import ToolResult
from breachload.tools.registry import default_registry


def _result(stdout: str, code: int = 0) -> ToolResult:
    return ToolResult(exit_code=code, stdout=stdout, stderr="", duration_s=0.1)


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestAppFinger:
    def test_detects_freepbx_with_version(self):
        a = AppFingerAdapter()
        a.build_command("http://10.129.110.230")
        body = ('HTTP/1.1 200 OK\r\n\r\n<title>FreePBX Administration</title>'
                '<link href="/admin/x?version=16.0.40.7">')
        st = EngagementState(name="t")
        notes = a.parse(_result(body), st)
        svc = st.hosts["10.129.110.230"].services["80/tcp"]
        assert any("webapp: FreePBX 16.0.40.7" in n for n in svc.notes)
        assert any("FreePBX" in n for n in notes)

    def test_detects_wordpress(self):
        a = AppFingerAdapter()
        a.build_command("http://10.10.10.5")
        body = 'HTTP/1.1 200 OK\r\n\r\n<meta name="generator" content="WordPress 6.2">'
        st = EngagementState(name="t")
        a.parse(_result(body), st)
        assert any("webapp: WordPress 6.2" in n
                   for n in st.hosts["10.10.10.5"].services["80/tcp"].notes)

    def test_no_match(self):
        a = AppFingerAdapter()
        a.build_command("http://10.10.10.5")
        assert "no known application" in a.parse(_result("<html>plain</html>"),
                                                 EngagementState(name="t"))[0]

    def test_feeds_webcve_matcher(self):
        # the full point: appfinger note -> web-CVE finding -> (auto-foothold)
        a = AppFingerAdapter()
        a.build_command("http://10.129.110.230")
        st = EngagementState(name="t")
        a.parse(_result("<title>FreePBX Administration</title>"), st)
        findings = WebCveMatcher.default().findings_for(st)
        assert any("CVE-2025-57819" in f.cve for f in findings)

    def test_command_is_clean(self):
        cmd = AppFingerAdapter().build_command("http://10.10.10.5")
        assert cmd[0] == "curl" and "-L" in cmd
        assert not any(c in tok for tok in cmd for c in (";", "|", "&", ">", "<"))


class TestPlannerRunsAppfinger:
    def test_appfinger_in_enum(self):
        st = EngagementState(name="t", phase=Phase.ENUM)
        st.upsert_host("10.10.10.5").upsert_service(Service(port=80, name="http"))
        for tool in ("httpx", "whatweb"):
            st.record_action(ActionRecord(phase=Phase.ENUM, tool=tool,
                                          command=[tool, "http://10.10.10.5:80"]))
        plan = Planner()._heuristic(st, _tools())
        assert plan.tool == "appfinger"
