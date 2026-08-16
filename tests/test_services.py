"""Service-enumeration adapters: snmp, nfs, ftp, redis."""

from breachload.core.llm import Planner
from breachload.core.state import EngagementState, Phase, Service
from breachload.tools.base import ToolResult
from breachload.tools.ftp import FtpAdapter
from breachload.tools.nfs import NfsAdapter
from breachload.tools.redis import RedisAdapter
from breachload.tools.registry import default_registry
from breachload.tools.snmp import SnmpAdapter

_FORBIDDEN = (";", "|", "&", "$(", "`", ">", "<")


def _result(stdout: str, code: int = 0) -> ToolResult:
    return ToolResult(exit_code=code, stdout=stdout, stderr="", duration_s=0.1)


def _no_shell_metachars(cmd):
    return not any(any(b in tok for b in _FORBIDDEN) for tok in cmd)


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestSnmp:
    def test_parses_oids_and_flags_public(self):
        a = SnmpAdapter()
        cmd = a.build_command("10.10.10.5")
        assert cmd[0] == "snmpwalk" and "10.10.10.5:161" in cmd and _no_shell_metachars(cmd)
        out = (".1.3.6.1.2.1.1.1.0 Linux dc 6.1\n"
               ".1.3.6.1.2.1.1.5.0 DC01\n"
               ".1.3.6.1.4.1.77.1.2.25.1.1 backup_password=Summer2025\n")
        st = EngagementState(name="t")
        notes = a.parse(_result(out), st)
        assert "10.10.10.5" in st.hosts
        assert "161/udp" in st.hosts["10.10.10.5"].services
        titles = [f.title for f in st.findings]
        assert any("community 'public'" in t for t in titles)
        assert any("credential" in t for t in titles)   # the password-looking OID
        assert any("OIDs readable" in n for n in notes)

    def test_no_response(self):
        a = SnmpAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("Timeout: No Response from 10.10.10.5", code=1),
                        EngagementState(name="t"))
        assert "no response" in notes[0]


class TestNfs:
    def test_parses_exports(self):
        a = NfsAdapter()
        a.build_command("10.10.10.5")
        st = EngagementState(name="t")
        notes = a.parse(_result("/srv/share *\n/data 10.10.10.0/24\n"), st)
        assert "2049/tcp" in st.hosts["10.10.10.5"].services
        assert len(st.findings) == 2
        assert any("*" in n for n in notes)

    def test_no_exports(self):
        a = NfsAdapter()
        a.build_command("10.10.10.5")
        assert "no exports" in a.parse(_result("", code=1), EngagementState(name="t"))[0]


class TestFtp:
    def test_anonymous_allowed_records_cred(self):
        a = FtpAdapter()
        a.build_command("10.10.10.5")
        st = EngagementState(name="t")
        notes = a.parse(_result("drwxr-xr-x 2 0 0 4096 Jan 1 pub\n"
                                "-rw-r--r-- 1 0 0 12 Jan 1 flag.txt\n"), st)
        assert "21/tcp" in st.hosts["10.10.10.5"].services
        assert any(c.username == "anonymous" for c in st.credentials)
        assert any("Anonymous FTP login" in f.title for f in st.findings)
        assert any("anonymous login OK" in n for n in notes)

    def test_denied(self):
        a = FtpAdapter()
        a.build_command("10.10.10.5")
        assert "denied" in a.parse(_result("", code=67), EngagementState(name="t"))[0]


class TestRedis:
    def test_unauth_flagged_high(self):
        a = RedisAdapter()
        a.build_command("10.10.10.5")
        st = EngagementState(name="t")
        notes = a.parse(_result("# Server\r\nredis_version:7.0.11\r\nos:Linux\r\n"), st)
        assert "6379/tcp" in st.hosts["10.10.10.5"].services
        assert any("Unauthenticated Redis" in f.title for f in st.findings)
        assert any("7.0.11" in n for n in notes)

    def test_auth_required(self):
        a = RedisAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("NOAUTH Authentication required."), EngagementState(name="t"))
        assert "authentication required" in notes[0]


class TestServicePlannerTriggers:
    def _state(self, svc):
        st = EngagementState(name="t", phase=Phase.ENUM)
        st.upsert_host("10.10.10.5").upsert_service(svc)
        return st

    def test_snmp_triggers(self):
        st = self._state(Service(port=161, protocol="udp", name="snmp"))
        assert Planner()._heuristic(st, _tools()).tool == "snmp"

    def test_ftp_triggers(self):
        st = self._state(Service(port=21, name="ftp"))
        assert Planner()._heuristic(st, _tools()).tool == "ftp"

    def test_redis_triggers(self):
        st = self._state(Service(port=6379, name="redis"))
        assert Planner()._heuristic(st, _tools()).tool == "redis"

    def test_nfs_triggers(self):
        st = self._state(Service(port=2049, name="nfs"))
        assert Planner()._heuristic(st, _tools()).tool == "nfs"
