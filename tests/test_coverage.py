"""Coverage additions: container/k8s escape parsing + BloodHound ingestion."""

from breachload.analysis.bloodhound import parse_bloodhound
from breachload.analysis.postexploit import loot, parse_container
from breachload.core.state import Severity


class TestContainerEscape:
    def test_docker_sock(self):
        findings = parse_container("srw-rw---- 1 root docker /var/run/docker.sock")
        assert any("docker socket" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("chroot /mnt" in f.exploit for f in findings)

    def test_k8s_token(self):
        findings = parse_container("/var/run/secrets/kubernetes.io/serviceaccount/token")
        assert any("kubernetes" in f.title.lower() for f in findings)

    def test_privileged_container(self):
        findings = parse_container("found /.dockerenv\nCapEff: cap_sys_admin,cap_net_raw")
        assert any("privileged container" in f.title.lower() for f in findings)

    def test_clean_host_no_findings(self):
        assert parse_container("uid=1000(bob) groups=1000(bob)") == []

    def test_wired_into_loot(self):
        findings, _ = loot("ls -la /var/run/docker.sock\n")
        assert any("docker socket" in f.title.lower() for f in findings)


class TestBloodHound:
    def test_kerberoast_and_asrep(self):
        data = {"data": [
            {"Properties": {"name": "SVC@CORP.LOCAL", "hasspn": True}},
            {"Properties": {"name": "NOAUTH@CORP.LOCAL", "dontreqpreauth": True}},
        ]}
        findings = parse_bloodhound(data)
        assert any("Kerberoastable" in f.title and "SVC" in f.title for f in findings)
        assert any("AS-REP" in f.title and "NOAUTH" in f.title for f in findings)

    def test_dangerous_ace(self):
        data = {"data": [
            {"Properties": {"name": "HELPDESK@CORP.LOCAL"},
             "Aces": [{"RightName": "GenericAll", "PrincipalSID": "S-1-5-21-x"}]},
        ]}
        findings = parse_bloodhound(data)
        acl = next(f for f in findings if f.title.startswith("ACL:"))
        assert "genericall" in acl.title and "bloodyAD" in acl.exploit

    def test_unconstrained_delegation(self):
        data = {"data": [{"Properties": {"name": "WS01@CORP.LOCAL",
                                         "unconstraineddelegation": True}}]}
        assert any("Unconstrained delegation" in f.title for f in parse_bloodhound(data))

    def test_tolerates_missing_keys(self):
        assert parse_bloodhound({}) == []
        assert parse_bloodhound({"data": [{}]}) == []


class TestRobustness:
    """Bug-hunt hardening: new code must not crash on empty/malformed input."""

    def test_bloodhound_malformed(self):
        assert parse_bloodhound({"data": [{"Aces": [{"RightName": "Unknown"}]}]}) == []
        assert parse_bloodhound({"data": "notalist"}) == []   # must not crash
        assert parse_bloodhound({"data": ["str", 5, None]}) == []
        assert parse_bloodhound("not a dict") == []

    def test_container_empty(self):
        assert parse_container("") == []

    def test_privesc_empty_enum(self):
        from breachload.analysis.privesc_auto import attempt_escalation
        from breachload.core.session import WebshellSession
        s = WebshellSession.from_spec("http://h/s.php?cmd=FUZZ")
        s.run = lambda c, **k: ""
        assert attempt_escalation(s, "", []).escalated is False

    def test_appfinger_headers_only(self):
        from breachload.core.state import EngagementState
        from breachload.tools.appfinger import AppFingerAdapter
        from breachload.tools.base import ToolResult
        a = AppFingerAdapter()
        a.build_command("http://10.10.10.5")
        r = a.parse(ToolResult(exit_code=0, stdout="HTTP/1.1 500\r\n\r\n", stderr="",
                               duration_s=0.1), EngagementState(name="t"))
        assert "no known application" in r[0]

    def test_rootsession_none_base_safe(self):
        # a RootSession loaded with a bad base must not crash from_dict
        from breachload.core.session import Session
        assert Session.from_dict({"kind": "root", "host": "h",
                                  "base": {"kind": "bad"}, "template": "{CMD}"}) is None
