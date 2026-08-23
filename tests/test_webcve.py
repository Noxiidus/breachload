"""Web-application version -> CVE matcher + guided exploitation."""

from breachload.analysis.analyzer import Analyzer
from breachload.analysis.webcve import WebCveEntry, WebCveMatcher, _find_version
from breachload.core.state import EngagementState, Service
from breachload.tools.base import ToolResult
from breachload.tools.whatweb import WhatWebAdapter


def _state_with(svc: Service) -> EngagementState:
    st = EngagementState(name="t")
    st.upsert_host("10.10.10.9").upsert_service(svc)
    return st


class TestFindVersion:
    def test_various_separators(self):
        assert _find_version("wordpress 6.2 metagenerator", "wordpress") == "6.2"
        assert _find_version("grafana/8.3.0", "grafana") == "8.3.0"
        assert _find_version("webapp: nginx ui 2.3.2", "nginx ui") == "2.3.2"

    def test_no_version(self):
        assert _find_version("wordpress metagenerator", "wordpress") is None


class TestRangeMatch:
    def _matcher(self):
        return WebCveMatcher([WebCveEntry(
            match=["grafana"], range=">=8.0.0,<8.3.1", cve="CVE-2021-43798",
            severity="high", name="Grafana path traversal",
            exploit="curl http://{TARGET}:{PORT}/x", note="read files")])

    def test_in_range_fires_with_filled_exploit(self):
        svc = Service(port=3000, name="http", notes=["webapp: Grafana 8.3.0"])
        findings = self._matcher().findings_for(_state_with(svc))
        assert len(findings) == 1
        f = findings[0]
        assert f.cve == ["CVE-2021-43798"]
        assert f.exploit == "curl http://10.10.10.9:3000/x"   # {TARGET}/{PORT} filled

    def test_out_of_range_skipped(self):
        svc = Service(port=3000, name="http", notes=["webapp: Grafana 9.1.0"])
        assert self._matcher().findings_for(_state_with(svc)) == []

    def test_missing_version_skipped_when_range_required(self):
        svc = Service(port=3000, name="http", notes=["whatweb: Grafana"])
        assert self._matcher().findings_for(_state_with(svc)) == []


class TestVersionAgnostic:
    def test_token_only_fires_as_lead(self):
        m = WebCveMatcher([WebCveEntry(
            match=["confluence"], range="", cve="CVE-2022-26134",
            severity="critical", name="Confluence OGNL", exploit="", note="")])
        svc = Service(port=8090, name="http", notes=["whatweb: Confluence"])
        findings = m.findings_for(_state_with(svc))
        assert len(findings) == 1
        assert "VERIFY" in findings[0].description


class TestBundledKb:
    def test_default_loads_and_matches_nginx_ui(self):
        m = WebCveMatcher.default()
        assert m.entries
        svc = Service(port=80, name="http", notes=["whatweb: Nginx UI"])
        findings = m.findings_for(_state_with(svc))
        assert any("nginx" in f.title.lower() for f in findings)

    def test_analyzer_wires_webcve(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.9").upsert_service(
            Service(port=3000, name="http", notes=["webapp: Grafana 8.3.0"]))
        added = Analyzer.default().analyze(st)
        assert any("Grafana" in f.title for f in added)


class TestWhatwebAppVersions:
    def test_app_version_note_emitted(self):
        a = WhatWebAdapter()
        a.build_command("http://10.10.10.9")
        stdout = ('[{"target":"http://10.10.10.9/","http_status":200,'
                  '"plugins":{"WordPress":{"version":["6.2"]},'
                  '"MetaGenerator":{"string":["WordPress 6.2"]}}}]')
        st = EngagementState(name="t")
        a.parse(ToolResult(exit_code=0, stdout=stdout, stderr="", duration_s=0.1), st)
        notes = st.hosts["10.10.10.9"].services["80/tcp"].notes
        assert any("webapp: WordPress 6.2" in n for n in notes)


class TestBughunt:
    def test_neighbouring_product_version_not_misattributed(self):
        # BUG-2: 'grafana' with no adjacent version must not borrow apache's.
        from breachload.analysis.webcve import _find_version
        hay = "grafana, apache 2.4.1"
        assert _find_version(hay, "grafana") is None
        assert _find_version("grafana 8.3.0, apache 2.4.1", "grafana") == "8.3.0"
