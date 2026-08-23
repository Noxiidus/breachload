"""ADCS certipy parsing + the new AD attack chains."""

from breachload.analysis.adcs import parse_certipy
from breachload.analysis.chains import ChainMatcher
from breachload.core.state import Credential, EngagementState, Finding, Service, Severity

_CERTIPY = """
Certificate Authorities
  0
    CA Name : corp-DC01-CA
    DNS Name : dc01.corp.local
Certificate Templates
  0
    Template Name : ESC1-Template
    [!] Vulnerabilities
      ESC1 : 'CORP.LOCAL\\Domain Users' can enroll, enrollee supplies subject
  1
    Template Name : UserAuth
    [!] Vulnerabilities
      ESC9 : Domain Users can enroll and template has no security extension
"""


class TestParseCertipy:
    def test_extracts_esc_findings_with_exploit(self):
        findings = parse_certipy(_CERTIPY)
        titles = [f.title for f in findings]
        assert any("ESC1" in t and "ESC1-Template" in t for t in titles)
        assert any("ESC9" in t and "UserAuth" in t for t in titles)
        assert all(f.severity == Severity.CRITICAL for f in findings)
        esc1 = next(f for f in findings if "ESC1" in f.title)
        assert "certipy req" in esc1.exploit and "corp-DC01-CA" in esc1.exploit
        assert "administrator" in esc1.exploit

    def test_esc9_exploit_has_upn_swap(self):
        findings = parse_certipy(_CERTIPY)
        esc9 = next(f for f in findings if "ESC9" in f.title)
        assert "account update" in esc9.exploit and "-upn administrator" in esc9.exploit

    def test_no_vulns_no_findings(self):
        assert parse_certipy("Certificate Templates\n  0\n    Template Name : Safe\n") == []

    def test_dedupes(self):
        doubled = _CERTIPY + _CERTIPY
        f1 = parse_certipy(_CERTIPY)
        f2 = parse_certipy(doubled)
        assert len(f1) == len(f2)   # same (template, esc) pairs collapse


class TestNewAdChains:
    def _dc_state_with_creds(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.11.10")
        h.upsert_service(Service(port=88, name="kerberos"))
        st.add_finding(Finding(title="Active Directory Domain Controller on 10.10.11.10",
                               host="10.10.11.10"))
        st.credentials.append(Credential(username="bob", secret="Pass1", kind="password"))
        return st

    def test_acl_and_shadow_and_esc9_chains_match(self):
        matched = {c.id for c in ChainMatcher.default().match(self._dc_state_with_creds())}
        assert {"ad-acl-abuse", "ad-shadow-credentials", "ad-adcs-esc9"} <= matched

    def test_esc9_renders_placeholders(self):
        cm = ChainMatcher.default()
        chain = next(c for c in cm.chains if c.id == "ad-adcs-esc9")
        steps = "\n".join(chain.render_steps(TARGET="10.10.11.10", DOMAIN="corp.local",
                                             USER="bob", PASS="Pass1"))
        assert "corp.local" in steps and "10.10.11.10" in steps


class TestBughunt:
    def test_esc_in_prose_not_flagged(self):
        # BUG-1: an ESC mention outside the Vulnerabilities section must not fire.
        text = ("Certificate Templates\n  0\n    Template Name : Web\n"
                "    Description : hardened against ESC1 and ESC8\n")
        assert parse_certipy(text) == []
