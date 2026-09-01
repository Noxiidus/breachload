"""Generalized Windows lateral-movement chains."""

from breachload.analysis.windows_lateral import (
    evilwinrm_argv,
    lateral_commands,
    psexec_argv,
    smbexec_argv,
    wmiexec_argv,
)
from breachload.core.state import Credential, EngagementState, Service


class TestArgv:
    def test_evilwinrm_password(self):
        argv = evilwinrm_argv("10.10.11.5", "bob", "pw")
        assert argv[0] == "evil-winrm" and "-p" in argv and "pw" in argv

    def test_evilwinrm_hash(self):
        argv = evilwinrm_argv("10.10.11.5", "bob", "aa" * 16, is_hash=True)
        assert "-H" in argv

    def test_wmiexec_hash_uses_dash_hashes(self):
        argv = wmiexec_argv("10.10.11.5", "bob", "aa" * 16,
                            domain="corp.local", is_hash=True)
        assert "-hashes" in argv and ":aa" in " ".join(argv)
        assert "corp.local/bob@10.10.11.5" in argv

    def test_psexec_password_target_form(self):
        argv = psexec_argv("10.10.11.5", "bob", "pw", domain="corp.local")
        assert "corp.local/bob:pw@10.10.11.5" in argv

    def test_smbexec_password(self):
        argv = smbexec_argv("10.10.11.5", "bob", "pw")
        assert argv[0] == "impacket-smbexec"


class TestLateralCommands:
    def test_windows_host_gets_four_techniques(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.11.5")
        h.os_guess = "Windows Server 2019"
        h.tags += ["dc", "domain:corp.local"]
        h.upsert_service(Service(port=445, name="smb"))
        st.credentials.append(Credential(username="bob", secret="pw",
                                         kind="password"))
        rows = lateral_commands(st)
        techs = {t.split(" ")[0].split("-")[0] for _h, t, _a in rows}
        # winrm, wmi, psexec, smbexec
        assert techs == {"winrm", "wmi", "psexec", "smbexec"}

    def test_pth_variant_when_credential_is_nt_hash(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.11.5")
        h.os_guess = "Windows"
        h.upsert_service(Service(port=445, name="smb"))
        st.credentials.append(Credential(username="admin", secret="a" * 32,
                                         kind="hash"))
        rows = lateral_commands(st)
        assert rows and all("-pth" in t for _h, t, _a in rows)

    def test_non_windows_host_skipped(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.5")
        h.upsert_service(Service(port=22, name="ssh"))
        st.credentials.append(Credential(username="bob", secret="pw",
                                         kind="password"))
        assert lateral_commands(st) == []

    def test_no_creds_no_rows(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.11.5").upsert_service(Service(port=445, name="smb"))
        assert lateral_commands(st) == []

    def test_non_hash_kind_hash_ignored(self):
        # a short "hash" string isn't a real NT hash and is skipped
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.11.5")
        h.upsert_service(Service(port=445, name="smb"))
        st.credentials.append(Credential(username="admin", secret="abc",
                                         kind="hash"))
        assert lateral_commands(st) == []
