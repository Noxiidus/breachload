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
        assert any("Users" in n and "share" in n for n in notes)

    def test_nothing_parsed(self):
        notes = NetexecAdapter().parse(_result("garbage"), EngagementState(name="t"))
        assert "nothing parsed" in notes[0]
