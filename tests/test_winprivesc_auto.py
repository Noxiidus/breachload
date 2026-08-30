"""Windows autonomous privesc — WinRM session, enum parse, escalation."""

from breachload.analysis.winprivesc_auto import (
    _parse_enum,
    _to_findings,
    attempt_win_escalation,
    run_win_enum,
)
from breachload.core.session import WinrmSession


class _FakeSession:
    def __init__(self, out_map=None, escalated_out=""):
        self.out_map = out_map or {}
        self.escalated_out = escalated_out
        self.calls = []

    def run(self, cmd, timeout=30, runner=None):
        self.calls.append(cmd)
        # Enum command hits — match by a stable substring.
        for token, out in self.out_map.items():
            if token in cmd:
                return out
        return self.escalated_out

    def to_dict(self):
        return {"kind": "winrm", "host": "10.10.11.5"}


class TestWinrmSession:
    def test_argv_and_dict(self):
        s = WinrmSession.from_spec("bob:pw@10.10.11.5")
        assert s.host == "10.10.11.5" and s.port == 5985
        argv = s._argv("whoami")
        assert argv[0] == "evil-winrm" and "-c" in argv and "whoami" in argv

    def test_from_dict_roundtrip(self):
        from breachload.core.session import Session
        d = WinrmSession.from_spec("a:b@1.2.3.4:5986").to_dict()
        s = Session.from_dict(d)
        assert isinstance(s, WinrmSession) and s.user == "a"


class TestParseEnum:
    def test_se_impersonate_flagged(self):
        raw = {"whoami": "PRIVILEGES INFORMATION\n"
               "SeImpersonatePrivilege        Impersonate a client   Enabled"}
        r = _parse_enum(raw)
        assert any("SeImpersonate" in f.title for f in r.findings)

    def test_always_install_elevated(self):
        raw = {"installed_elevated_hklm": "    AlwaysInstallElevated    REG_DWORD    0x1",
               "installed_elevated_hkcu": "    AlwaysInstallElevated    REG_DWORD    0x1"}
        r = _parse_enum(raw)
        assert any("AlwaysInstallElevated" in f.title for f in r.findings)

    def test_aie_needs_both_keys(self):
        # HKLM=1 but HKCU=0 -> no finding
        raw = {"installed_elevated_hklm": "AlwaysInstallElevated  REG_DWORD  0x1",
               "installed_elevated_hkcu": "AlwaysInstallElevated  REG_DWORD  0x0"}
        assert not _parse_enum(raw).findings

    def test_unquoted_service_path(self):
        raw = {"services": "PathName=C:\\Program Files\\Vuln App\\vuln.exe\n"
                            "StartMode=Auto\n"}
        r = _parse_enum(raw)
        assert any("Unquoted service path" in f.title for f in r.findings)

    def test_autologon_creds_collected(self):
        raw = {"autologon":
               "    AutoAdminLogon    REG_SZ    1\n"
               "    DefaultUserName   REG_SZ    admin\n"
               "    DefaultPassword   REG_SZ    Winter2025!\n"
               "    DefaultDomainName REG_SZ    CORP\n"}
        r = _parse_enum(raw)
        creds = r.creds
        assert len(creds) == 1
        assert creds[0].username == "CORP\\admin" and creds[0].secret == "Winter2025!"


class TestEscalation:
    def test_se_impersonate_escalates_when_flag_read(self):
        enum = _parse_enum({"whoami": "SeImpersonatePrivilege ... Enabled"})
        sess = _FakeSession(escalated_out="abcdef1234567890abcdef1234567890\n")
        r = attempt_win_escalation(sess, enum)
        assert r.escalated and r.vector.startswith("SeImpersonate")
        assert len(r.proof) == 32

    def test_no_vector_no_escalation(self):
        enum = _parse_enum({"whoami": "no privs"})
        r = attempt_win_escalation(_FakeSession(), enum)
        assert not r.escalated

    def test_aie_escalates_when_flag_read(self):
        enum = _parse_enum({
            "installed_elevated_hklm": "AlwaysInstallElevated REG_DWORD 0x1",
            "installed_elevated_hkcu": "AlwaysInstallElevated REG_DWORD 0x1"})
        sess = _FakeSession(escalated_out="deadbeefdeadbeefdeadbeefdeadbeef")
        r = attempt_win_escalation(sess, enum)
        assert r.escalated and "AlwaysInstallElevated" in r.vector


class TestFullFlow:
    def test_run_enum_uses_session(self):
        sess = _FakeSession(out_map={"whoami /all": "SeImpersonatePrivilege ... Enabled",
                                     "AlwaysInstallElevated": "",
                                     "systeminfo": "OS Name: Windows Server 2019"})
        r = run_win_enum(sess)
        assert any("SeImpersonate" in f.title for f in r.findings)
        # every enum command was issued
        assert len(sess.calls) >= 5

    def test_to_findings_severity_maps(self):
        raw = {"whoami": "SeImpersonatePrivilege Enabled",
               "installed_elevated_hklm": "AlwaysInstallElevated REG_DWORD 0x1",
               "installed_elevated_hkcu": "AlwaysInstallElevated REG_DWORD 0x1"}
        fs = _to_findings(_parse_enum(raw), host="1.2.3.4")
        sevs = {f.severity.value for f in fs}
        assert "critical" in sevs and "high" in sevs
