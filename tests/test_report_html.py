"""Self-contained HTML report renderer."""

from breachload.core.state import (
    ActionRecord,
    Credential,
    EngagementState,
    Finding,
    Phase,
    Service,
    Severity,
)
from breachload.report.html import render_html


def _state() -> EngagementState:
    st = EngagementState(name="demo", phase=Phase.EXPLOIT)
    h = st.upsert_host("10.10.10.5")
    h.upsert_service(Service(port=80, name="http", product="nginx", version="1.18"))
    st.add_finding(Finding(title="SQLi in login", severity=Severity.CRITICAL,
                           description="union-based", host="10.10.10.5",
                           cve=["CVE-2025-1"], exploit="sqlmap -u http://x"))
    st.add_finding(Finding(title="Info leak", severity=Severity.LOW, description="banner"))
    st.credentials.append(Credential(username="admin", secret="pw", kind="password"))
    st.record_action(ActionRecord(phase=Phase.RECON, tool="nmap",
                                  command=["nmap", "-sV", "10.10.10.5"], exit_code=0))
    return st


class TestRenderHtml:
    def test_is_self_contained_html(self):
        html = render_html(_state())
        assert html.startswith("<!doctype html>")
        assert "</body></html>" in html
        assert "<style>" in html          # inline CSS, no external asset
        assert "src=" not in html and "cdn" not in html.lower()
        assert "<link" not in html and "http-equiv" not in html

    def test_contains_sections(self):
        html = render_html(_state())
        for token in ("Executive summary", "Findings", "Hosts", "Credentials",
                      "Activity timeline"):
            assert token in html

    def test_severity_badges_present(self):
        html = render_html(_state())
        assert "CRITICAL" in html and "LOW" in html

    def test_escapes_html_injection(self):
        st = EngagementState(name="x")
        st.add_finding(Finding(title="<script>alert(1)</script>",
                               severity=Severity.HIGH, description="x"))
        html = render_html(st)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_empty_state_ok(self):
        html = render_html(EngagementState(name="empty"))
        assert html.startswith("<!doctype html>")
        assert "Executive summary" in html
