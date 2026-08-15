"""netexec adapter — SMB / AD enrichment parsing."""

from breachload.core.state import EngagementState, Severity
from breachload.tools.base import ToolResult
from breachload.tools.netexec import NetexecAdapter

_BANNER = ("SMB  10.10.11.42  445  DC01  [*] Windows Server 2019 Build 17763 x64 "
           "(name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)")


def _result(text: str) -> ToolResult:
    return ToolResult(exit_code=0, stdout=text, stderr="", duration_s=0.1)


class TestBuildCommand:
    def test_unauthenticated(self):
        assert NetexecAdapter().build_command("10.10.11.42") == ["nxc", "smb", "10.10.11.42"]

    def test_authenticated(self):
        cmd = NetexecAdapter().build_command("10.10.11.42", user="bob", password="pw",
                                             extra=["--shares"])
        assert cmd == ["nxc", "smb", "10.10.11.42", "-u", "bob", "-p", "pw", "--shares"]


class TestParse:
    def test_banner_extracts_domain_os_hostname(self):
        st = EngagementState(name="t")
        NetexecAdapter().parse(_result(_BANNER), st)
        host = st.hosts["10.10.11.42"]
        assert "domain:corp.local" in host.tags
        assert "DC01" in host.hostnames
        assert host.os_guess and "Windows Server 2019" in host.os_guess
        assert "445/tcp" in host.services

    def test_pwned_credential_and_finding(self):
        st = EngagementState(name="t")
        text = _BANNER + "\nSMB  10.10.11.42  445  DC01  [+] corp.local\\svc:Passw0rd (Pwn3d!)"
        NetexecAdapter().parse(_result(text), st)
        assert any(c.username == "svc" and c.secret == "Passw0rd" and c.validated
                   for c in st.credentials)
        assert any(f.severity == Severity.HIGH and "Administrative access" in f.title
                   for f in st.findings)

    def test_readable_share_noted(self):
        st = EngagementState(name="t")
        text = _BANNER + "\nSMB  10.10.11.42  445  DC01  Users   READ            "
        notes = NetexecAdapter().parse(_result(text), st)
        assert any("share Users (READ)" in n for n in notes)

    def test_status_line_is_not_a_second_banner(self):
        # A "[*] Enumerated shares" status line must not be parsed as a host banner
        # (it has no (name:...)), which previously produced a bogus "workgroup" host.
        st = EngagementState(name="t")
        text = _BANNER + "\nSMB  10.10.11.42  445  DC01  [*] Enumerated shares"
        notes = NetexecAdapter().parse(_result(text), st)
        banner_notes = [n for n in notes if n.startswith("10.10.11.42")]
        assert len(banner_notes) == 1                       # only the real banner
        assert "workgroup" not in " ".join(notes)

    def test_workgroup_is_not_tagged_as_domain(self):
        # A standalone Windows host reports (domain:WORKGROUP) — not an AD domain.
        st = EngagementState(name="t")
        line = ("SMB  10.10.10.5  445  WS01  [*] Windows 10 (name:WS01) "
                "(domain:WORKGROUP) (signing:False)")
        NetexecAdapter().parse(_result(line), st)
        assert not any(t.startswith("domain:") for t in st.hosts["10.10.10.5"].tags)

    def test_nothing_parsed(self):
        notes = NetexecAdapter().parse(_result("garbage"), EngagementState(name="t"))
        assert "nothing parsed" in notes[0]
