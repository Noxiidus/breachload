"""Markdown report rendering."""

from breachload.core.state import (
    ActionRecord,
    Artifact,
    Credential,
    EngagementState,
    Finding,
    Phase,
    Service,
    Severity,
)
from breachload.report.engine import render_markdown


def _populated() -> EngagementState:
    st = EngagementState(name="acme", phase=Phase.VULN)
    host = st.upsert_host("10.10.10.5")
    host.os_guess = "Linux 5.x"
    host.upsert_service(Service(port=80, name="http", product="Apache httpd", version="2.4.49"))
    host.upsert_service(Service(port=445, name="microsoft-ds"))
    st.add_finding(Finding(
        title="Apache path traversal", severity=Severity.CRITICAL, host="10.10.10.5",
        service_key="80/tcp", description="Vulnerable Apache.", remediation="Upgrade.",
        evidence="GET /cgi-bin/.%2e/ HTTP/1.1", cve=["CVE-2021-41773"],
    ))
    st.add_finding(Finding(title="Server banner", severity=Severity.INFO, host="10.10.10.5"))
    st.credentials.append(Credential(username="bob", kind="username",
                                     service_key="10.10.10.5:445/tcp"))
    st.add_artifact(Artifact(name="rev.elf", kind="payload", tool="msfvenom", platform="linux",
                             path="/x/rev.elf"))
    st.record_action(ActionRecord(phase=Phase.RECON, tool="nmap",
                                  command=["nmap", "10.10.10.5"], exit_code=0))
    st.record_action(ActionRecord(phase=Phase.EXPLOIT, tool="hydra",
                                  command=["hydra", "10.10.10.5"], approved=False))
    return st


class TestRenderMarkdown:
    def setup_method(self):
        self.md = render_markdown(_populated())

    def test_header_and_summary(self):
        assert self.md.startswith("# Engagement report — acme")
        assert "## Summary" in self.md
        assert "Hosts: **1**" in self.md
        assert "1 critical" in self.md and "1 info" in self.md

    def test_hosts_table(self):
        assert "## Hosts & services" in self.md
        assert "10.10.10.5" in self.md
        assert "Apache httpd 2.4.49" in self.md
        assert "80/tcp" in self.md and "445/tcp" in self.md

    def test_findings_ordered_by_severity(self):
        assert "[CRITICAL] Apache path traversal" in self.md
        assert "[INFO] Server banner" in self.md
        assert self.md.index("[CRITICAL]") < self.md.index("[INFO]")

    def test_finding_details(self):
        assert "CVE-2021-41773" in self.md
        assert "**Remediation:** Upgrade." in self.md
        assert "GET /cgi-bin/.%2e/" in self.md

    def test_credentials_and_artifacts(self):
        assert "## Credentials" in self.md and "bob" in self.md
        assert "## Generated artifacts" in self.md and "rev.elf" in self.md

    def test_timeline_shows_status(self):
        assert "## Activity timeline" in self.md
        assert "nmap" in self.md and "exit 0" in self.md
        assert "blocked/skipped" in self.md   # the declined hydra action

    def test_finding_includes_repro_from_history(self):
        # The nmap command targeted 10.10.10.5 and succeeded, so it appears as a
        # reproduction step under that host's finding.
        assert "**Reproduce:**" in self.md
        assert "nmap 10.10.10.5" in self.md


class TestEmptyState:
    def test_minimal_report_no_crash(self):
        md = render_markdown(EngagementState(name="empty"))
        assert md.startswith("# Engagement report — empty")
        assert "no findings" in md
        # Optional sections are omitted when empty.
        assert "## Findings" not in md
        assert "## Credentials" not in md
