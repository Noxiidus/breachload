"""Attack-chain template matching."""

from breachload.analysis.chains import ChainMatcher
from breachload.core.state import EngagementState, Finding, Service, Severity


def _host(addr, os_guess=None, services=()):
    st = EngagementState(name="t")
    h = st.upsert_host(addr)
    h.os_guess = os_guess
    for svc in services:
        h.upsert_service(svc)
    return st


class TestChainMatcher:
    def setup_method(self):
        self.m = ChainMatcher.default()

    def test_loads_chains(self):
        ids = {c.id for c in self.m.chains}
        assert {"eternalblue", "ftp-anon", "smb-quickwins", "tomcat-manager"} <= ids

    def test_eternalblue_needs_smb_and_windows(self):
        win = _host("10.0.0.9", "Windows 7", [Service(port=445, name="microsoft-ds")])
        assert any(c.id == "eternalblue" for c in self.m.match(win))
        # Same SMB port but Linux → the os_contains condition fails.
        lin = _host("10.0.0.5", "Linux 5.x", [Service(port=445, name="microsoft-ds")])
        assert not any(c.id == "eternalblue" for c in self.m.match(lin))

    def test_ftp_anon_matches_port_21(self):
        st = _host("10.0.0.5", "Linux", [Service(port=21, name="ftp")])
        assert any(c.id == "ftp-anon" for c in self.m.match(st))

    def test_product_condition(self):
        st = _host("10.0.0.5", None, [Service(port=8080, name="http", product="Apache Tomcat")])
        assert any(c.id == "tomcat-manager" for c in self.m.match(st))

    def test_finding_condition(self):
        st = EngagementState(name="t")
        st.upsert_host("10.0.0.5")
        st.add_finding(Finding(title="Apache path traversal", severity=Severity.HIGH))
        assert any(c.id == "web-traversal" for c in self.m.match(st))

    def test_no_conditions_met_no_match(self):
        st = _host("10.0.0.5", "Linux", [Service(port=22, name="ssh")])
        assert self.m.match(st) == []

    def test_matches_sorted_by_priority(self):
        st = _host("10.0.0.9", "Windows", [Service(port=445, name="microsoft-ds")])
        matched = self.m.match(st)
        assert [c.priority for c in matched] == sorted(c.priority for c in matched)

    def test_ad_authed_chain_needs_credentials(self):
        from breachload.core.state import Credential, Finding, Severity
        st = EngagementState(name="t")
        st.upsert_host("10.0.0.1")
        st.add_finding(Finding(title="Active Directory Domain Controller on 10.0.0.1",
                               severity=Severity.INFO))
        # No creds yet: the authenticated AD chain must not match.
        assert not any(c.id == "ad-authed-enum" for c in self.m.match(st))
        # Unauthenticated AD enum still matches on the DC finding alone.
        assert any(c.id == "ad-unauth-enum" for c in self.m.match(st))
        # Add a credential -> the authenticated chain now matches.
        st.credentials.append(Credential(username="bob", secret="pw", kind="password"))
        assert any(c.id == "ad-authed-enum" for c in self.m.match(st))

    def test_ad_chain_renders_user_pass_domain(self):
        chain = next(c for c in self.m.chains if c.id == "ad-kerberoast")
        steps = chain.render_steps(TARGET="10.0.0.1", USER="bob", PASS="pw",
                                   DOMAIN="corp.local")
        blob = "\n".join(steps)
        assert "bob" in blob and "pw" in blob and "corp.local" in blob
        assert "{USER}" not in blob and "{DOMAIN}" not in blob

    def test_render_and_target(self):
        st = _host("10.0.0.9", "Windows", [Service(port=445, name="microsoft-ds")])
        chain = next(c for c in self.m.match(st) if c.id == "eternalblue")
        target = self.m.target_for(chain, st)
        assert target == "10.0.0.9"
        steps = chain.render_steps(TARGET=target, LHOST="10.10.14.9", LPORT=4444)
        assert any("10.0.0.9" in s for s in steps)
        assert any("10.10.14.9" in s for s in steps)
