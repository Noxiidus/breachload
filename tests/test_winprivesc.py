"""Windows privilege-escalation playbook + parsers."""

from breachload.analysis.winprivesc import (
    parse_privileges,
    parse_winpeas,
    playbook_lines,
)
from breachload.core.state import Severity


class TestPlaybook:
    def test_fills_lhost_and_references_winpeas(self):
        lines = "\n".join(playbook_lines("10.10.14.7", http_port=8001))
        assert "10.10.14.7:8001/winPEASx64.exe" in lines
        assert "whoami /priv" in lines
        assert "breachload winprivesc" in lines


class TestPrivileges:
    def test_seimpersonate_flagged(self):
        text = "SeImpersonatePrivilege        Impersonate a client   Enabled"
        findings = parse_privileges(text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Potato" in findings[0].description

    def test_disabled_privilege_skipped(self):
        text = "SeImpersonatePrivilege        Impersonate a client   Disabled"
        assert parse_privileges(text) == []

    def test_unknown_privilege_ignored(self):
        assert parse_privileges("SeChangeNotifyPrivilege   Enabled") == []


class TestWinpeas:
    def test_always_install_elevated(self):
        text = "HKLM ... AlwaysInstallElevated  REG_DWORD  0x1\nHKCU ... AlwaysInstallElevated 0x1"
        findings = parse_winpeas(text)
        aie = next(f for f in findings if "AlwaysInstallElevated" in f.title)
        assert aie.severity == Severity.HIGH and "msiexec" in aie.exploit

    def test_unquoted_service_path(self):
        text = r"C:\Program Files\Vuln Service\service.exe"
        assert any("Unquoted service path" in f.title for f in parse_winpeas(text))

    def test_autologon_password(self):
        text = "DefaultPassword    REG_SZ    Sup3rS3cret!"
        findings = parse_winpeas(text)
        assert any("Autologon" in f.title for f in findings)

    def test_combined_and_deduped(self):
        text = ("SeImpersonatePrivilege Enabled\nSeImpersonatePrivilege Enabled\n"
                "AlwaysInstallElevated 0x1")
        titles = [f.title for f in parse_winpeas(text)]
        assert len(titles) == len(set(titles))   # no duplicate titles
