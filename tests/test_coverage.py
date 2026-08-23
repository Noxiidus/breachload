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
