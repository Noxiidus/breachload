"""Adapter tests — parse real sample outputs into state, and check command safety.

These lock the parser contract: given a captured tool output, the resulting
state must be correct. Commands must be argv lists free of shell metacharacters
so the validator accepts them.
"""

from breachload.core.state import EngagementState, Severity
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator
from breachload.tools.base import ToolResult
from breachload.tools.ffuf import FfufAdapter
from breachload.tools.nmap import NmapAdapter
from breachload.tools.nuclei import NucleiAdapter
from breachload.tools.registry import allowed_binaries, default_registry
from breachload.tools.whatweb import WhatWebAdapter

_FORBIDDEN = (";", "|", "&", "$(", "`", ">", "<")


def _result(stdout: str, code: int = 0) -> ToolResult:
    return ToolResult(exit_code=code, stdout=stdout, stderr="", duration_s=0.1)


def _no_shell_metachars(cmd: list[str]) -> bool:
    return not any(any(b in tok for b in _FORBIDDEN) for tok in cmd)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="10.10.10.5" addrtype="ipv4"/>
  <hostnames><hostname name="web.lab"/></hostnames>
  <ports>
   <port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.41"/>
   </port>
   <port protocol="tcp" portid="22">
    <state state="closed"/>
    <service name="ssh"/>
   </port>
  </ports>
  <os><osmatch name="Linux 5.x"/></os>
 </host>
</nmaprun>"""

WHATWEB_JSON = (
    '[{"target":"http://10.10.10.5","http_status":200,'
    '"plugins":{"Apache":{"version":["2.4.41"]},'
    '"PHP":{"version":["7.4.3"]},'
    '"Country":{"string":["RESERVED"]},'
    '"HTTPServer":{"string":["Apache/2.4.41 (Ubuntu)"]}}}]'
)

FFUF_JSON = (
    '{"commandline":"ffuf","results":['
    '{"input":{"FUZZ":"admin"},"status":200,"length":1234,"url":"http://10.10.10.5/admin","host":"10.10.10.5"},'
    '{"input":{"FUZZ":"login"},"status":301,"length":0,"url":"http://10.10.10.5/login","host":"10.10.10.5"}]}'
)

NUCLEI_JSONL = (
    '{"template-id":"apache-detect","info":{"name":"Apache Detection","severity":"info"},'
    '"host":"http://10.10.10.5","matched-at":"http://10.10.10.5"}\n'
    '{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical",'
    '"classification":{"cve-id":["cve-2021-41773"]}},'
    '"host":"http://10.10.10.5","matched-at":"http://10.10.10.5/cgi-bin/.%2e/"}'
)


class TestNmap:
    def test_parses_open_ports_and_os(self):
        st = EngagementState(name="t")
        NmapAdapter().parse(_result(NMAP_XML), st)
        host = st.hosts["10.10.10.5"]
        assert host.os_guess == "Linux 5.x"
        assert "web.lab" in host.hostnames
        assert "80/tcp" in host.services       # open port kept
        assert "22/tcp" not in host.services   # closed port dropped
        svc = host.services["80/tcp"]
        assert svc.product == "Apache httpd" and svc.version == "2.4.41"

    def test_command_is_safe_argv(self):
        cmd = NmapAdapter().build_command("10.10.10.5")
        assert cmd[0] == "nmap" and _no_shell_metachars(cmd)


class TestWhatWeb:
    def test_parses_server_and_techs(self):
        st = EngagementState(name="t")
        notes = WhatWebAdapter().parse(_result(WHATWEB_JSON), st)
        svc = st.hosts["10.10.10.5"].services["80/tcp"]
        assert svc.product and "Apache" in svc.product
        assert any("PHP" in n for n in svc.notes)
        assert notes and "10.10.10.5" in notes[0]

    def test_build_command_adds_scheme(self):
        cmd = WhatWebAdapter().build_command("10.10.10.5")
        assert "http://10.10.10.5" in cmd and _no_shell_metachars(cmd)


class TestFfuf:
    def test_parses_paths_into_finding(self):
        st = EngagementState(name="t")
        WhatWebAdapter().parse(_result(WHATWEB_JSON), st)  # seed the http service
        notes = FfufAdapter().parse(_result(FFUF_JSON), st)
        assert len(notes) == 2
        assert st.findings and st.findings[0].host == "10.10.10.5"
        svc = st.hosts["10.10.10.5"].services["80/tcp"]
        assert any("ffuf" in n for n in svc.notes)

    def test_build_command_injects_fuzz(self):
        cmd = FfufAdapter().build_command("http://10.10.10.5")
        assert any("FUZZ" in tok for tok in cmd) and _no_shell_metachars(cmd)

    def test_non_default_port_attaches_to_correct_service(self):
        st = EngagementState(name="t")
        host = st.upsert_host("10.10.10.5")
        from breachload.core.state import Service
        host.upsert_service(Service(port=8080, name="http-proxy"))
        ffuf_8080 = ('{"results":[{"input":{"FUZZ":"api"},"status":200,"length":5,'
                     '"url":"http://10.10.10.5:8080/api","host":"10.10.10.5"}]}')
        FfufAdapter().parse(_result(ffuf_8080), st)
        assert any("ffuf" in n for n in host.services["8080/tcp"].notes)
        assert st.findings[0].service_key == "8080/tcp"


class TestNuclei:
    def test_maps_severity_and_cve(self):
        st = EngagementState(name="t")
        notes = NucleiAdapter().parse(_result(NUCLEI_JSONL), st)
        assert len(notes) == 2
        sevs = {f.severity for f in st.findings}
        assert Severity.CRITICAL in sevs and Severity.INFO in sevs
        crit = next(f for f in st.findings if f.severity == Severity.CRITICAL)
        assert "CVE-2021-41773" in crit.cve

    def test_ignores_non_json_lines(self):
        st = EngagementState(name="t")
        NucleiAdapter().parse(_result("garbage\n" + NUCLEI_JSONL), st)
        assert len(st.findings) == 2


class TestRegistry:
    def test_all_adapters_registered_and_authorized(self):
        reg = default_registry()
        assert {"nmap", "whatweb", "ffuf", "nuclei"} <= set(reg)
        bins = allowed_binaries(reg)
        assert {"nmap", "whatweb", "ffuf", "nuclei"} <= bins

    def test_registered_commands_pass_validator(self):
        reg = default_registry()
        scope = Scope.from_config(["10.10.10.0/24"])
        v = Validator(scope, allowed_binaries(reg), Risk.EXPLOIT)
        for adapter in reg.values():
            cmd = adapter.build_command("10.10.10.5")
            d = v.check(cmd, adapter.risk)
            assert d.allowed, f"{adapter.name} produced an unrunnable command: {d.reason}"
