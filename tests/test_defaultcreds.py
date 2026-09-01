"""Generalized default-credential sweep."""

from breachload.analysis.defaultcreds import (
    SERVICE_DEFAULTS,
    WEBAPP_DEFAULTS,
    credential_from_hit,
    sweep_commands,
)
from breachload.core.state import EngagementState, Service


def _state(svcs):
    st = EngagementState(name="t")
    h = st.upsert_host("10.10.10.5")
    for s in svcs:
        h.upsert_service(s)
    return st


class TestServiceSweep:
    def test_mysql_blank_root(self):
        cmds = sweep_commands(_state([Service(port=3306, name="mysql")]))
        assert cmds
        techs = {t for _h, t, _a in cmds}
        assert "mysql-blank" in techs

    def test_ssh_default_pair(self):
        cmds = sweep_commands(_state([Service(port=22, name="ssh")]))
        argvs = [a for _h, _t, a in cmds]
        assert any(a[0] == "sshpass" and "root@10.10.10.5" in a for a in argvs)

    def test_snmp_default_community(self):
        cmds = sweep_commands(_state([Service(port=161, protocol="udp", name="snmp")]))
        argvs = [" ".join(a) for _h, _t, a in cmds]
        assert any("public" in a for a in argvs)

    def test_ftp_anonymous(self):
        cmds = sweep_commands(_state([Service(port=21, name="ftp")]))
        assert any("ftp://anonymous:anonymous@10.10.10.5" in " ".join(a)
                   for _h, _t, a in cmds)


class TestWebappSweep:
    def test_wordpress_default_from_note(self):
        svc = Service(port=80, name="http", notes=["webapp: WordPress 6.2"])
        cmds = sweep_commands(_state([svc]))
        techs = {t for _h, t, _a in cmds}
        assert "wordpress-default" in techs

    def test_tomcat_manager_defaults(self):
        svc = Service(port=8080, name="http", product="Apache Tomcat")
        techs = {t for _h, t, _a in sweep_commands(_state([svc]))}
        assert "tomcat-default" in techs

    def test_no_match_no_output(self):
        svc = Service(port=80, name="http")
        assert sweep_commands(_state([svc])) == []


class TestCredentialRecord:
    def test_credential_from_hit_shape(self):
        c = credential_from_hit("root", "root", "1.2.3.4", "3306/tcp", "mysql-default")
        assert c.username == "root" and c.validated
        assert c.service_key == "1.2.3.4:3306/tcp"
        assert "default-cred" in (c.source or "")


class TestCoverage:
    def test_class_coverage_wide_enough(self):
        # Rough sanity: the class table covers the recurring services + top web apps.
        for k in ("mysql", "postgres", "mssql", "ssh", "ftp", "smb", "snmp"):
            assert k in SERVICE_DEFAULTS
        for k in ("wordpress", "tomcat", "grafana", "gitlab", "jenkins",
                  "webmin", "glpi"):
            assert k in WEBAPP_DEFAULTS
