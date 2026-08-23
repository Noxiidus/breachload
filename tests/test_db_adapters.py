"""Database / SMTP enumeration adapters: mysql, postgres, mssql, smtp."""

from breachload.core.llm import Planner
from breachload.core.state import EngagementState, Phase, Service
from breachload.tools.base import ToolResult
from breachload.tools.mssql import MssqlAdapter
from breachload.tools.mysql import MysqlAdapter
from breachload.tools.postgres import PostgresAdapter
from breachload.tools.registry import default_registry
from breachload.tools.smtp import SmtpAdapter

_FORBIDDEN = (";", "|", "&", "$(", "`", ">", "<", "\n")


def _result(stdout: str, code: int = 0, stderr: str = "") -> ToolResult:
    return ToolResult(exit_code=code, stdout=stdout, stderr=stderr, duration_s=0.1)


def _no_shell_metachars(cmd):
    return not any(any(b in tok for b in _FORBIDDEN) for tok in cmd)


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestMysql:
    def test_blank_login_flagged(self):
        a = MysqlAdapter()
        cmd = a.build_command("10.10.10.5")
        assert cmd[0] == "mysql" and _no_shell_metachars(cmd)
        st = EngagementState(name="t")
        notes = a.parse(_result("Database\ninformation_schema\nmysql\napp\n"), st)
        assert "3306/tcp" in st.hosts["10.10.10.5"].services
        assert any("blank/weak root" in f.title for f in st.findings)
        assert any(c.username == "root" for c in st.credentials)
        assert any("login OK" in n for n in notes)

    def test_access_denied(self):
        a = MysqlAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("", code=1, stderr="ERROR 1045 Access denied for user"),
                        EngagementState(name="t"))
        assert "access denied" in notes[0]


class TestPostgres:
    def test_trust_login_flagged(self):
        a = PostgresAdapter()
        cmd = a.build_command("10.10.10.5")
        assert cmd[0] == "psql" and "-w" in cmd and _no_shell_metachars(cmd)
        st = EngagementState(name="t")
        notes = a.parse(_result("PostgreSQL 14.2 on x86_64-pc-linux-gnu\n"), st)
        assert "5432/tcp" in st.hosts["10.10.10.5"].services
        assert any("trust/blank login" in f.title for f in st.findings)
        assert "login OK" in notes[0]

    def test_auth_failed(self):
        a = PostgresAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("", code=2, stderr="psql: error: authentication failed"),
                        EngagementState(name="t"))
        assert "authentication failed" in notes[0]


class TestMssql:
    def test_blank_sa_flagged(self):
        a = MssqlAdapter()
        cmd = a.build_command("10.10.10.5")
        assert cmd[0] == "nxc" and cmd[1] == "mssql" and _no_shell_metachars(cmd)
        st = EngagementState(name="t")
        out = "MSSQL  10.10.10.5  1433  SQL01  [+] SQL01\\sa: (Pwn3d!)\n"
        notes = a.parse(_result(out), st)
        assert any("blank sa login" in f.title for f in st.findings)
        assert any(f.exploit for f in st.findings)
        assert "login OK" in notes[0]

    def test_login_failed(self):
        a = MssqlAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("MSSQL  10.10.10.5  [-] SQL01\\sa: login failed"),
                        EngagementState(name="t"))
        assert "failed" in notes[0]


class TestSmtp:
    def test_users_enumerated(self):
        a = SmtpAdapter()
        cmd = a.build_command("10.10.10.5")
        assert cmd[0] == "smtp-user-enum" and _no_shell_metachars(cmd)
        st = EngagementState(name="t")
        out = "root@10.10.10.5 exists\nadmin@10.10.10.5 exists\nnobody@10.10.10.5\n"
        notes = a.parse(_result(out), st)
        assert "25/tcp" in st.hosts["10.10.10.5"].services
        assert any("username enumeration" in f.title.lower() for f in st.findings)
        assert "root" in notes[0]

    def test_missing_userlist(self):
        a = SmtpAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("", code=1, stderr="Unable to open user file"),
                        EngagementState(name="t"))
        assert "list not found" in notes[0]


class TestPlannerTriggers:
    def _state(self, svc):
        st = EngagementState(name="t", phase=Phase.ENUM)
        st.upsert_host("10.10.10.5").upsert_service(svc)
        return st

    def test_mysql_triggers(self):
        st = self._state(Service(port=3306, name="mysql"))
        assert Planner()._heuristic(st, _tools()).tool == "mysql"

    def test_postgres_triggers(self):
        st = self._state(Service(port=5432, name="postgresql"))
        assert Planner()._heuristic(st, _tools()).tool == "postgres"

    def test_mssql_triggers(self):
        st = self._state(Service(port=1433, name="ms-sql-s"))
        assert Planner()._heuristic(st, _tools()).tool == "mssql"

    def test_smtp_triggers(self):
        st = self._state(Service(port=25, name="smtp"))
        assert Planner()._heuristic(st, _tools()).tool == "smtp"
