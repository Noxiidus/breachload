"""Additional service adapters: ldap, rpc, rsync, mongodb."""

from breachload.core.llm import Planner
from breachload.core.state import EngagementState, Phase, Service
from breachload.tools.base import ToolResult
from breachload.tools.ldap import LdapAdapter
from breachload.tools.mongodb import MongoAdapter
from breachload.tools.registry import default_registry
from breachload.tools.rpc import RpcAdapter
from breachload.tools.rsync import RsyncAdapter

_FORBIDDEN = (";", "|", "&", "$(", "`", ">", "<", "\n")


def _result(stdout: str, code: int = 0, stderr: str = "") -> ToolResult:
    return ToolResult(exit_code=code, stdout=stdout, stderr=stderr, duration_s=0.1)


def _clean(cmd):
    return not any(any(b in tok for b in _FORBIDDEN) for tok in cmd)


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestLdap:
    def test_anon_bind_extracts_domain(self):
        a = LdapAdapter()
        assert _clean(a.build_command("10.10.10.5"))
        st = EngagementState(name="t")
        out = ("namingContexts: DC=corp,DC=local\n"
               "namingContexts: CN=Configuration,DC=corp,DC=local\n")
        notes = a.parse(_result(out), st)
        h = st.hosts["10.10.10.5"]
        assert "389/tcp" in h.services
        assert any(t == "domain:corp.local" for t in h.tags)
        assert any("Anonymous LDAP bind" in f.title for f in st.findings)
        assert "corp.local" in notes[0]

    def test_no_contexts(self):
        a = LdapAdapter()
        a.build_command("10.10.10.5")
        assert "no naming contexts" in a.parse(_result(""), EngagementState(name="t"))[0]


class TestRpc:
    def test_portmapper_lists_nfs(self):
        a = RpcAdapter()
        assert _clean(a.build_command("10.10.10.5"))
        out = ("   program vers proto   port  service\n"
               "    100000    4   tcp    111  portmapper\n"
               "    100003    3   tcp   2049  nfs\n"
               "    100005    1   udp  20048  mountd\n")
        st = EngagementState(name="t")
        notes = a.parse(_result(out), st)
        assert "111/tcp" in st.hosts["10.10.10.5"].services
        assert any("portmapper exposes" in f.title for f in st.findings)
        assert any("nfs" in n for n in notes)


class TestRsync:
    def test_modules_flagged(self):
        a = RsyncAdapter()
        assert _clean(a.build_command("10.10.10.5"))
        out = "backups     \tBackup share\nsrc         \tSource code\n"
        st = EngagementState(name="t")
        notes = a.parse(_result(out), st)
        assert "873/tcp" in st.hosts["10.10.10.5"].services
        assert any("rsync modules exposed" in f.title for f in st.findings)
        assert any(f.exploit for f in st.findings)
        assert "backups" in notes[0]

    def test_refused(self):
        a = RsyncAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("", code=10, stderr="connection refused"),
                        EngagementState(name="t"))
        assert "could not connect" in notes[0]


class TestMongo:
    def test_unauth_flagged(self):
        a = MongoAdapter()
        assert _clean(a.build_command("10.10.10.5"))
        st = EngagementState(name="t")
        out = '{ databases: [ { name: "admin" }, { name: "app" } ], totalSize: 123 }'
        notes = a.parse(_result(out), st)
        assert "27017/tcp" in st.hosts["10.10.10.5"].services
        assert any("Unauthenticated MongoDB" in f.title for f in st.findings)
        assert "UNAUTH" in notes[0]

    def test_auth_required(self):
        a = MongoAdapter()
        a.build_command("10.10.10.5")
        notes = a.parse(_result("MongoServerError: command requires authentication"),
                        EngagementState(name="t"))
        assert "authentication required" in notes[0]


class TestPlannerTriggers:
    def _state(self, svc):
        st = EngagementState(name="t", phase=Phase.ENUM)
        st.upsert_host("10.10.10.5").upsert_service(svc)
        return st

    def test_ldap_triggers(self):
        assert Planner()._heuristic(self._state(Service(port=389, name="ldap")),
                                    _tools()).tool == "ldap"

    def test_rpc_triggers(self):
        assert Planner()._heuristic(self._state(Service(port=111, name="rpcbind")),
                                    _tools()).tool == "rpc"

    def test_rsync_triggers(self):
        assert Planner()._heuristic(self._state(Service(port=873, name="rsync")),
                                    _tools()).tool == "rsync"

    def test_mongo_triggers(self):
        assert Planner()._heuristic(self._state(Service(port=27017, name="mongodb")),
                                    _tools()).tool == "mongodb"
