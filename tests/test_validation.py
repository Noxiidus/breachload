"""Proof / validation tracking on findings + report rendering."""

from breachload.core.state import EngagementState, Finding, Severity
from breachload.report.engine import render_markdown
from breachload.report.html import render_html


class TestFindingValidation:
    def test_default_suspected(self):
        f = Finding(title="x", severity=Severity.HIGH)
        assert f.validation == "suspected" and f.proof == ""

    def test_confirm_sets_state_and_proof(self):
        f = Finding(title="x", severity=Severity.HIGH)
        f.confirm("read /root/root.txt")
        assert f.validation == "confirmed"
        assert f.proof == "read /root/root.txt"

    def test_confirm_returns_self(self):
        f = Finding(title="x", severity=Severity.HIGH).confirm()
        assert f.validation == "confirmed"


class TestReportShowsValidation:
    def _state(self):
        st = EngagementState(name="t")
        st.add_finding(Finding(title="SQLi", severity=Severity.CRITICAL,
                               validation="confirmed", proof="dumped users table"))
        st.add_finding(Finding(title="Old nginx", severity=Severity.LOW))
        return st

    def test_markdown_status_and_counts(self):
        md = render_markdown(self._state())
        assert "CONFIRMED" in md and "suspected" in md
        assert "Confirmed (proven): **1**" in md
        assert "dumped users table" in md

    def test_html_status_badges(self):
        html = render_html(self._state())
        assert "CONFIRMED" in html and "SUSPECTED" in html
        assert "dumped users table" in html
        # confirmed card present
        assert ">Confirmed<" in html
