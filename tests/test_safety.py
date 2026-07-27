"""Safety-layer tests. These guard the invariants the autonomous model relies on."""

from breachload.safety.scope import Scope, extract_targets
from breachload.safety.validator import Risk, Validator


def make_scope() -> Scope:
    return Scope.from_config(
        ["10.10.10.0/24", "10.10.11.55", "*.target.example"],
        exclude=["10.10.10.1"],
    )


class TestScope:
    def test_allows_in_network(self):
        assert make_scope().allows("10.10.10.5")

    def test_allows_single_host(self):
        assert make_scope().allows("10.10.11.55")

    def test_excluded_host_denied(self):
        assert not make_scope().allows("10.10.10.1")

    def test_out_of_scope_denied(self):
        assert not make_scope().allows("8.8.8.8")

    def test_wildcard_domain(self):
        s = make_scope()
        assert s.allows("sub.target.example")
        assert s.allows("target.example")
        assert not s.allows("target.evil.com")


class TestExtractTargets:
    def test_extracts_ip_host_url(self):
        found = extract_targets(["-sV", "http://10.10.10.5/app", "sub.target.example"])
        assert "10.10.10.5" in found
        assert "sub.target.example" in found


class TestValidator:
    def setup_method(self):
        self.v = Validator(make_scope(), {"nmap"}, Risk.ACTIVE)

    def test_in_scope_recon_allowed_no_confirm(self):
        d = self.v.check(["nmap", "-sV", "10.10.10.5"], Risk.RECON)
        assert d.allowed and not d.needs_confirmation

    def test_out_of_scope_blocked(self):
        assert not self.v.check(["nmap", "8.8.8.8"], Risk.RECON).allowed

    def test_unknown_binary_blocked(self):
        assert not self.v.check(["rm", "-rf", "/"], Risk.RECON).allowed

    def test_shell_metacharacter_blocked(self):
        assert not self.v.check(["nmap", "10.10.10.5;whoami"], Risk.RECON).allowed

    def test_above_threshold_needs_confirmation(self):
        d = self.v.check(["nmap", "10.10.10.5"], Risk.EXPLOIT)
        assert d.allowed and d.needs_confirmation

    def test_excluded_target_blocked(self):
        assert not self.v.check(["nmap", "10.10.10.1"], Risk.RECON).allowed


class TestAdvisorThreshold:
    """auto_threshold=None (advisor mode) must confirm even passive actions."""

    def setup_method(self):
        self.v = Validator(make_scope(), {"nmap"}, None)

    def test_passive_needs_confirmation(self):
        d = self.v.check(["nmap", "10.10.10.5"], Risk.PASSIVE)
        assert d.allowed and d.needs_confirmation

    def test_still_blocks_out_of_scope(self):
        assert not self.v.check(["nmap", "8.8.8.8"], Risk.PASSIVE).allowed


class TestModeThreshold:
    """EngagementConfig.mode maps to an effective confirmation threshold."""

    def _cfg(self, mode):
        from breachload.core.config import EngagementConfig
        return EngagementConfig(name="t", mode=mode, auto_threshold="active")

    def test_advisor_is_none(self):
        assert self._cfg("advisor").effective_threshold is None

    def test_semi_auto_is_recon(self):
        assert self._cfg("semi-auto").effective_threshold == Risk.RECON

    def test_full_auto_uses_configured(self):
        assert self._cfg("full-auto").effective_threshold == Risk.ACTIVE
