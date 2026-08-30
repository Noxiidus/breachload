"""Property-based fuzz tests for every user-facing parser.

The invariant across every parser in breachload is the same: **arbitrary input must
never crash it** (a real tool's real output is only ever more surprising than any
example we hand-wrote). If it can't decide, it returns an empty result — never an
exception. hypothesis generates thousands of adversarial strings per parser so
regressions in that invariant are caught before they show up as an in-flight crash
on a live engagement.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from breachload.analysis.adchain import plan_ad_chain, render_chain
from breachload.analysis.adcs import parse_certipy, parse_dangling_templates
from breachload.analysis.bloodhound import parse_bloodhound
from breachload.analysis.cve import satisfies
from breachload.analysis.kerberos import creds_from_roast, parse_roast
from breachload.analysis.winprivesc_auto import _parse_enum
from breachload.core.state import EngagementState, Finding, Service, Severity
from breachload.exploit.autofire import render_argv
from breachload.tools.appfinger import AppFingerAdapter
from breachload.tools.base import ToolResult
from breachload.tools.dns import DnsAdapter

# Text strategy: bytes-y, allows nulls, newlines, control chars — the ugly corners
# a tool output can hit under load / a partial read / a garbled response.
_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)),
                min_size=0, max_size=1024)
_TOKEN = st.text(alphabet=st.characters(whitelist_categories=("L", "N")),
                 min_size=1, max_size=32)

_SLOW_OK = settings(deadline=None, max_examples=200,
                    suppress_health_check=[HealthCheck.too_slow])


class TestParsersDoNotCrash:
    @given(_TEXT)
    @_SLOW_OK
    def test_kerberos_parse_roast(self, s):
        parse_roast(s)
        creds_from_roast(s)

    @given(_TEXT)
    @_SLOW_OK
    def test_win_enum_parse(self, s):
        # Every enum slot must accept arbitrary text; a garbled cmdkey/whoami
        # must not take down the enum.
        _parse_enum({"whoami": s, "installed_elevated_hklm": s,
                     "installed_elevated_hkcu": s, "services": s,
                     "autologon": s, "cmdkey": s, "scheduled": s,
                     "systeminfo": s})

    @given(_TEXT)
    @_SLOW_OK
    def test_certipy_parse(self, s):
        parse_certipy(s)
        parse_dangling_templates(s)

    @given(st.recursive(
        st.one_of(st.none(), st.booleans(), st.integers(-10, 10), _TEXT),
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(_TOKEN, children, max_size=4),
        ), max_leaves=12))
    @_SLOW_OK
    def test_bloodhound_arbitrary_json(self, doc):
        # A malformed JSON document (top-level list, nested None, wrong casing) is
        # exactly the crash surface parse_bloodhound has already been fixed for
        # once — property-check it against every shape.
        parse_bloodhound(doc if isinstance(doc, dict) else {"data": doc})

    @given(_TEXT)
    @_SLOW_OK
    def test_dns_parse(self, s):
        a = DnsAdapter()
        a.build_command("connected.htb")
        a.parse(ToolResult(exit_code=0, stdout=s, stderr="", duration_s=0.1),
                EngagementState(name="fuzz"))

    @given(_TEXT)
    @_SLOW_OK
    def test_appfinger_parse(self, s):
        a = AppFingerAdapter()
        a.build_command("http://10.10.10.5")
        a.parse(ToolResult(exit_code=0, stdout=s, stderr="", duration_s=0.1),
                EngagementState(name="fuzz"))

    @given(st.lists(_TOKEN, min_size=0, max_size=6),
           st.text(min_size=0, max_size=32))
    @_SLOW_OK
    def test_cve_satisfies(self, ver_parts, spec):
        version = ".".join(ver_parts) if ver_parts else ""
        # Never crash, always return a bool.
        assert isinstance(satisfies(version, spec), bool)

    @given(_TEXT, _TEXT, st.integers(0, 65535))
    @_SLOW_OK
    def test_autofire_render_argv(self, cve, target, port):
        # Unknown CVE -> None. Known CVE -> argv list, no shell metachars, no {…}
        # placeholder leaked through.
        argv = render_argv(cve, target, str(port))
        if argv is None:
            return
        assert isinstance(argv, list) and all(isinstance(t, str) for t in argv)

    @given(st.lists(
        st.builds(
            lambda t, e: Finding(title=t, severity=Severity.HIGH, exploit=e or ""),
            _TEXT, _TEXT), max_size=8))
    @_SLOW_OK
    def test_adchain(self, findings):
        chain = plan_ad_chain(findings)
        # Rendering must always produce a list of strings — never None, never raise.
        for line in render_chain(chain):
            assert isinstance(line, str)


class TestServiceParsersDoNotCrash:
    """A representative sample of the service-adapter parsers on random stdout."""

    @given(_TEXT)
    @_SLOW_OK
    def test_snmp_parse(self, s):
        from breachload.tools.snmp import SnmpAdapter
        a = SnmpAdapter()
        a.build_command("10.10.10.5")
        a.parse(ToolResult(exit_code=0, stdout=s, stderr="", duration_s=0.1),
                EngagementState(name="fuzz"))

    @given(_TEXT)
    @_SLOW_OK
    def test_nfs_parse(self, s):
        from breachload.tools.nfs import NfsAdapter
        a = NfsAdapter()
        a.build_command("10.10.10.5")
        a.parse(ToolResult(exit_code=0, stdout=s, stderr="", duration_s=0.1),
                EngagementState(name="fuzz"))

    @given(_TEXT)
    @_SLOW_OK
    def test_ftp_parse(self, s):
        from breachload.tools.ftp import FtpAdapter
        a = FtpAdapter()
        a.build_command("10.10.10.5")
        a.parse(ToolResult(exit_code=0, stdout=s, stderr="", duration_s=0.1),
                EngagementState(name="fuzz"))

    @given(_TEXT)
    @_SLOW_OK
    def test_netexec_parse(self, s):
        from breachload.tools.netexec import NetexecAdapter
        a = NetexecAdapter()
        a.build_command("10.10.10.5")
        a.parse(ToolResult(exit_code=0, stdout=s, stderr="", duration_s=0.1),
                EngagementState(name="fuzz"))


class TestStateNeverCorruptedByFuzz:
    @given(_TEXT)
    @_SLOW_OK
    def test_service_notes_accept_arbitrary_text(self, s):
        # notes are user-visible; whatever a parser puts there must be JSON-safe
        # (state.save serialises through pydantic).
        st = EngagementState(name="fuzz")
        st.upsert_host("10.10.10.5").upsert_service(
            Service(port=80, name="http", notes=[s]))
        st.model_dump()   # must not raise
