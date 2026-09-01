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
from breachload.tools.vhostfuzz import VhostFuzzAdapter
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

    def test_full_ports_flag(self):
        cmd = NmapAdapter().build_command("10.10.10.5", ports="-")
        assert "-p-" in cmd and _no_shell_metachars(cmd)
        # a specific port list still uses -p <list>
        cmd2 = NmapAdapter().build_command("10.10.10.5", ports="80,443")
        assert "-p" in cmd2 and cmd2[cmd2.index("-p") + 1] == "80,443"

    def test_mac_only_host_is_skipped(self):
        # A MAC address (e.g. from an ARP result) is not a scannable target and
        # must not be keyed into state as a bogus host.
        xml = ('<?xml version="1.0"?><nmaprun><host>'
               '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
               '<ports><port protocol="tcp" portid="22"><state state="open"/>'
               '<service name="ssh"/></port></ports></host></nmaprun>')
        st = EngagementState(name="t")
        NmapAdapter().parse(_result(xml), st)
        assert st.hosts == {}

    def test_ipv6_host_is_parsed(self):
        xml = ('<?xml version="1.0"?><nmaprun><host>'
               '<address addr="dead:beef::1" addrtype="ipv6"/>'
               '<ports><port protocol="tcp" portid="80"><state state="open"/>'
               '<service name="http"/></port></ports></host></nmaprun>')
        st = EngagementState(name="t")
        NmapAdapter().parse(_result(xml), st)
        assert "dead:beef::1" in st.hosts and "80/tcp" in st.hosts["dead:beef::1"].services


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

    def test_redirect_pivots_to_named_vhost(self):
        # A 301 to a named vhost must add that host + its HTTP service so the
        # planner enumerates it next, plus a finding flagging /etc/hosts.
        st = EngagementState(name="t")
        redirect_json = (
            '[{"target":"http://10.10.10.5","http_status":301,'
            '"plugins":{"nginx":{"string":["nginx/1.28.0"]},'
            '"RedirectLocation":{"string":["http://paperwork.htb/"]}}}]'
        )
        notes = WhatWebAdapter().parse(_result(redirect_json), st)
        assert "paperwork.htb" in st.hosts
        assert "80/tcp" in st.hosts["paperwork.htb"].services
        assert any("paperwork.htb" in n for n in notes)
        assert any("virtual host" in f.title for f in st.findings)

    def test_ip_redirect_does_not_pivot(self):
        # A redirect to a bare IP reveals no new vhost — must not create a host.
        st = EngagementState(name="t")
        redirect_json = (
            '[{"target":"http://10.10.10.5","http_status":301,'
            '"plugins":{"RedirectLocation":{"string":["http://10.10.10.9/app"]}}}]'
        )
        WhatWebAdapter().parse(_result(redirect_json), st)
        assert "10.10.10.9" not in st.hosts

    def test_empty_exit0_notes_hanging_root(self):
        # Connected but got nothing usable (a streaming/hanging root) — the note
        # must explain that, not read as a plain scan miss.
        notes = WhatWebAdapter().parse(_result("", code=0), EngagementState(name="t"))
        assert "no data" in notes[0] or "hang" in notes[0]


class TestFfuf:
    def test_parses_paths_into_finding(self):
        st = EngagementState(name="t")
        WhatWebAdapter().parse(_result(WHATWEB_JSON), st)  # seed the http service
        notes = FfufAdapter().parse(_result(FFUF_JSON), st)
        assert len(notes) == 2
        assert st.findings and st.findings[0].host == "10.10.10.5"
        svc = st.hosts["10.10.10.5"].services["80/tcp"]
        assert any("ffuf" in n for n in svc.notes)

    def test_reads_json_from_output_file(self):
        # ffuf's real JSON arrives via the tool-managed OUTFILE, not stdout.
        st = EngagementState(name="t")
        WhatWebAdapter().parse(_result(WHATWEB_JSON), st)
        res = ToolResult(exit_code=0, stdout="", stderr="", duration_s=0.1,
                         output_file=FFUF_JSON)
        notes = FfufAdapter().parse(res, st)
        assert len(notes) == 2
        assert any("ffuf" in n for n in st.hosts["10.10.10.5"].services["80/tcp"].notes)

    def test_build_command_injects_fuzz(self):
        cmd = FfufAdapter().build_command("http://10.10.10.5")
        assert any("FUZZ" in tok for tok in cmd) and _no_shell_metachars(cmd)

    def test_build_command_adds_extensions(self):
        cmd = FfufAdapter().build_command("http://10.10.10.5", extensions="php, txt,.html")
        assert "-e" in cmd
        assert cmd[cmd.index("-e") + 1] == ".php,.txt,.html"
        # JSON must go to a real file (OUTFILE), never /dev/stdout, or -s corrupts it.
        assert "{OUTFILE}" in cmd and "/dev/stdout" not in cmd
        # ffuf's -o writes to exactly the given path, so the marker IS the file.
        assert FfufAdapter().output_file_suffix == ""
        # auto-calibration filters blanket-redirect false positives.
        assert "-ac" in cmd

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


VHOSTFUZZ_JSON = ('{"results":[{"input":{"FUZZ":"chat"},"status":200,"length":3421,'
                  '"url":"http://paperwork.htb/","host":"paperwork.htb"}]}')


class TestVhostFuzz:
    def test_parses_vhost_into_host_and_finding(self):
        st = EngagementState(name="t")
        res = ToolResult(exit_code=0, stdout="", stderr="", duration_s=0.1,
                         output_file=VHOSTFUZZ_JSON)
        notes = VhostFuzzAdapter().parse(res, st)
        assert "chat.paperwork.htb" in st.hosts
        assert "80/tcp" in st.hosts["chat.paperwork.htb"].services
        assert any("Virtual host discovered" in f.title for f in st.findings)
        assert any("chat.paperwork.htb" in n for n in notes)

    def test_build_command_fuzzes_host_header(self):
        cmd = VhostFuzzAdapter().build_command("paperwork.htb")
        assert "Host: FUZZ.paperwork.htb" in cmd
        assert "{OUTFILE}" in cmd and "-ac" in cmd and _no_shell_metachars(cmd)

    def test_no_vhosts_discovered(self):
        st = EngagementState(name="t")
        res = ToolResult(exit_code=0, stdout="", stderr="", duration_s=0.1,
                         output_file='{"results":[]}')
        notes = VhostFuzzAdapter().parse(res, st)
        assert "no virtual hosts" in notes[0]


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

    def test_cve_id_as_string_is_not_split_into_chars(self):
        # Some templates emit classification.cve-id as a bare string, not a list.
        import json
        line = json.dumps({
            "info": {"name": "Bug", "severity": "high",
                     "classification": {"cve-id": "CVE-2024-1234"}},
            "matched-at": "http://10.10.10.5", "host": "10.10.10.5",
        })
        st = EngagementState(name="t")
        NucleiAdapter().parse(_result(line), st)
        assert st.findings[0].cve == ["CVE-2024-1234"]


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


class TestNucleiCvssAndProof:
    def test_cvss_score_and_confirmed_marker(self):
        import json

        from breachload.core.state import EngagementState
        from breachload.tools.base import ToolResult
        from breachload.tools.nuclei import NucleiAdapter
        match = {
            "template-id": "CVE-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical",
                     "description": "log4j RCE",
                     "classification": {"cve-id": ["CVE-2021-44228"],
                                        "cvss-score": 10.0}},
            "matched-at": "http://10.10.10.5:8080/",
            "host": "10.10.10.5"}
        result = ToolResult(exit_code=0, stdout=json.dumps(match) + "\n",
                            stderr="", duration_s=0.0)
        st = EngagementState(name="t")
        NucleiAdapter().parse(result, st)
        assert st.findings and st.findings[0].cvss == 10.0
        assert st.findings[0].validation == "confirmed"
        assert "CVE-2021-44228" in st.findings[0].cve

    def test_cvss_missing_is_none(self):
        import json

        from breachload.core.state import EngagementState
        from breachload.tools.base import ToolResult
        from breachload.tools.nuclei import NucleiAdapter
        match = {"template-id": "x", "info": {"name": "x", "severity": "low"},
                 "matched-at": "http://x/"}
        st = EngagementState(name="t")
        NucleiAdapter().parse(ToolResult(exit_code=0, stdout=json.dumps(match),
                                         stderr="", duration_s=0.0), st)
        assert st.findings and st.findings[0].cvss is None
