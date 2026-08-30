"""Active Kerberos — command builders + roast parsing."""

from breachload.analysis.kerberos import (
    asrep_command,
    creds_from_roast,
    kerberoast_command,
    parse_roast,
    userenum_command,
)

_ASREP_OUT = (
    "[*] Getting TGT for svc-web\n"
    "$krb5asrep$23$svc-web@CORP.LOCAL:aabbcc00112233...deadbeef\n"
    "[*] Getting TGT for guest\n"
    "$krb5asrep$23$guest@CORP.LOCAL:1122334455...cafebabe\n"
)
_TGS_OUT = (
    "ServicePrincipalName  Name    MemberOf\n"
    "MSSQLSvc/db.corp.local sqlsvc\n"
    "$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc~db*$aaaa...$bbbb....\n"
)


class TestCommands:
    def test_asrep_command(self):
        cmd = asrep_command("corp.local", "10.10.11.5", "users.txt")
        assert "impacket-GetNPUsers" in cmd[0]
        assert "corp.local/" in cmd and "-no-pass" in cmd
        assert "10.10.11.5" in cmd and "users.txt" in cmd

    def test_kerberoast_command(self):
        cmd = kerberoast_command("corp.local", "10.10.11.5", "bob", "pw")
        assert "corp.local/bob:pw" in cmd and "-request" in cmd

    def test_userenum_command(self):
        cmd = userenum_command("corp.local", "10.10.11.5", "users.txt")
        assert cmd[0] == "kerbrute" and "userenum" in cmd


class TestParse:
    def test_parses_asrep(self):
        findings = parse_roast(_ASREP_OUT, host="10.10.11.5")
        titles = [f.title for f in findings]
        assert any("svc-web" in t for t in titles)
        assert any("guest" in t for t in titles)
        assert all(f.severity.value == "high" for f in findings)
        assert any("18200" in f.exploit for f in findings)

    def test_parses_tgs(self):
        findings = parse_roast(_TGS_OUT)
        assert any("sqlsvc" in f.title for f in findings)
        assert any("13100" in f.exploit for f in findings)

    def test_creds_from_roast(self):
        creds = creds_from_roast(_ASREP_OUT + _TGS_OUT)
        assert len(creds) == 3
        assert all(c.kind == "hash" for c in creds)
        users = {c.username for c in creds}
        assert "svc-web" in users and "sqlsvc" in users

    def test_dedup(self):
        creds = creds_from_roast(_ASREP_OUT + _ASREP_OUT)
        assert len(creds) == 2

    def test_empty(self):
        assert parse_roast("") == []
        assert creds_from_roast("nothing here") == []
