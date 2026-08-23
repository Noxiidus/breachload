"""Auto-fire read-only exploit probes: table, adapter, and EXPLOIT-phase planner."""

from breachload.core.llm import Planner
from breachload.core.state import EngagementState, Finding, Phase, Service
from breachload.exploit.autofire import AUTO_PROBES, probe_for, render_argv
from breachload.tools.base import ToolResult
from breachload.tools.exploitprobe import ExploitProbeAdapter
from breachload.tools.registry import default_registry

_FORBIDDEN = (";", "|", "&", "$(", "`", ">", "<", "\n")


def _tools():
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry().values()]


class TestProbeTable:
    def test_all_probes_are_clean_readonly_curl(self):
        for cve, probe in AUTO_PROBES.items():
            argv = probe["argv"]
            assert argv[0] == "curl", cve
            # no shell metacharacters anywhere (injection guard)
            assert not any(any(b in tok for b in _FORBIDDEN) for tok in argv), cve
            # read-only HTTP: no custom write method; any --data must be a GET (-G),
            # which sends it as a query string, not a POST/PUT body.
            assert "-X" not in argv and "--request" not in argv, cve
            if any(t.startswith("--data") or t == "-d" for t in argv):
                assert "-G" in argv, f"{cve}: --data without -G is not a read-only GET"

    def test_render_fills_placeholders(self):
        argv = render_argv("CVE-2021-43798", "10.10.10.9", 3000)
        assert any("10.10.10.9:3000" in tok for tok in argv)

    def test_unknown_cve(self):
        assert probe_for("CVE-0000-0000") is None
        assert render_argv("CVE-0000-0000", "t", 80) is None


class TestExploitProbeAdapter:
    def test_loots_creds_and_flags(self):
        a = ExploitProbeAdapter()
        cmd = a.build_command("10.10.10.9", cve="CVE-2023-23752", port=80)
        assert cmd[0] == "curl"
        st = EngagementState(name="t")
        body = 'user":"joomla_db","password":"S3cr3tDBpass" flag{looted_it}'
        notes = a.parse(ToolResult(exit_code=0, stdout=body, stderr="", duration_s=0.1), st)
        assert any("Exploit probe fired" in f.title for f in st.findings)
        assert any(c.secret == "S3cr3tDBpass" for c in st.credentials)
        assert "flag{looted_it}" in st.flags
        assert any("flag" in n or "looted" in n for n in notes)

    def test_no_response(self):
        a = ExploitProbeAdapter()
        a.build_command("10.10.10.9", cve="CVE-2021-43798", port=3000)
        notes = a.parse(ToolResult(exit_code=7, stdout="", stderr="", duration_s=0.1),
                        EngagementState(name="t"))
        assert "no response" in notes[0]


class TestExploitPhasePlanner:
    def _state_with_finding(self):
        st = EngagementState(name="t", phase=Phase.EXPLOIT)
        st.upsert_host("10.10.10.9").upsert_service(Service(port=3000, name="http"))
        st.add_finding(Finding(title="Grafana path traversal (CVE-2021-43798)",
                               host="10.10.10.9", service_key="3000/tcp",
                               cve=["CVE-2021-43798"]))
        return st

    def test_fires_probe_for_matching_finding(self):
        plan = Planner()._heuristic(self._state_with_finding(), _tools())
        assert plan.tool == "exploit-probe"
        assert plan.args["cve"] == "CVE-2021-43798" and plan.args["port"] == 3000

    def test_does_not_refire(self):
        st = self._state_with_finding()
        # simulate the probe already fired (its recorded finding present)
        st.add_finding(Finding(title="Exploit probe fired: CVE-2021-43798 on 10.10.10.9:3000",
                               host="10.10.10.9"))
        plan = Planner()._heuristic(st, _tools())
        assert plan.action == "phase_complete"

    def test_no_probe_for_rce_finding(self):
        st = EngagementState(name="t", phase=Phase.EXPLOIT)
        st.add_finding(Finding(title="Cacti RCE (CVE-2022-46169)", host="10.10.10.9",
                               cve=["CVE-2022-46169"]))   # RCE: not in the auto-fire table
        assert Planner()._heuristic(st, _tools()).action == "phase_complete"


class TestFreepbx:
    def test_freepbx_kb_matches_and_probe_exists(self):
        from breachload.analysis.webcve import WebCveMatcher
        from breachload.core.state import EngagementState, Service
        st = EngagementState(name="t")
        st.upsert_host("10.129.110.230").upsert_service(
            Service(port=80, name="http", notes=["whatweb: FreePBX"]))
        findings = WebCveMatcher.default().findings_for(st)
        assert any("CVE-2025-57819" in f.cve for f in findings)
        # and it is auto-fireable (read-only SQLi confirm)
        assert probe_for("CVE-2025-57819") is not None
        argv = render_argv("CVE-2025-57819", "10.129.110.230", 80)
        assert any("ajax.php" in t for t in argv) and any("EXTRACTVALUE" in t for t in argv)
