"""DNS adapter — zone transfer harvest."""

from breachload.core.state import EngagementState, Service
from breachload.tools.dns import DnsAdapter
from breachload.tools.base import ToolResult


def _res(stdout: str, code: int = 0) -> ToolResult:
    return ToolResult(exit_code=code, stdout=stdout, stderr="", duration_s=0.1)


_ZONE = """connected.htb.\t\t604800\tIN\tSOA\tns1.connected.htb. admin.connected.htb. 2 604800 86400 2419200 604800
connected.htb.\t\t604800\tIN\tNS\tns1.connected.htb.
connected.htb.\t\t604800\tIN\tA\t10.10.11.5
www.connected.htb.\t604800\tIN\tA\t10.10.11.5
internal.connected.htb.\t604800\tIN\tA\t172.16.5.10
mail.connected.htb.\t604800\tIN\tMX\t10 mail.connected.htb.
"""


class TestDnsAdapter:
    def test_command_infers_domain_from_hostname(self):
        cmd = DnsAdapter().build_command("connected.htb")
        assert "axfr" in cmd and "connected.htb" in cmd and cmd[0] == "dig"

    def test_command_uses_explicit_domain(self):
        cmd = DnsAdapter().build_command("10.10.11.5", domain="corp.local")
        assert "corp.local" in cmd and "@10.10.11.5" in cmd

    def test_successful_axfr_harvests_hosts(self):
        a = DnsAdapter()
        a.build_command("connected.htb")
        st = EngagementState(name="t")
        notes = a.parse(_res(_ZONE), st)
        # internal + www + apex A records became hosts
        assert "172.16.5.10" in st.hosts
        assert "10.10.11.5" in st.hosts
        assert any("internal.connected.htb" in t for t in st.hosts["172.16.5.10"].tags)
        assert any("AXFR succeeded" in n for n in notes)

    def test_axfr_finding_recorded(self):
        a = DnsAdapter()
        a.build_command("connected.htb")
        st = EngagementState(name="t")
        a.parse(_res(_ZONE), st)
        assert any("zone transfer" in f.title.lower() for f in st.findings)

    def test_refused_axfr_is_quiet(self):
        a = DnsAdapter()
        a.build_command("10.10.11.5", domain="corp.local")
        st = EngagementState(name="t")
        notes = a.parse(_res("; Transfer failed."), st)
        assert any("refused" in n for n in notes)
        assert not st.findings

    def test_no_data_note(self):
        a = DnsAdapter()
        a.build_command("10.10.11.5", domain="corp.local")
        notes = a.parse(_res(""), EngagementState(name="t"))
        assert any("no zone data" in n for n in notes)

    def test_planner_schedules_dns_on_port_53(self):
        from breachload.core.llm import Planner
        from breachload.core.state import Phase
        from breachload.tools.registry import default_registry
        tools = [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
                 for a in default_registry().values()]
        st = EngagementState(name="t", phase=Phase.ENUM)
        st.upsert_host("10.10.11.5").upsert_service(
            Service(port=53, name="domain", state="open"))
        plan = Planner()._heuristic(st, tools)
        assert plan.tool == "dns"
