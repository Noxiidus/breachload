"""AD kill-chain composer — ordering and technique mapping."""

from breachload.analysis.adchain import plan_ad_chain, render_chain
from breachload.core.state import Finding, Severity


def _f(title, exploit=""):
    return Finding(title=title, severity=Severity.HIGH, description="", exploit=exploit)


class TestOrdering:
    def test_dcsync_before_kerberoast(self):
        findings = [
            _f("Kerberoastable account: svc_sql"),
            _f("ACL: AllExtendedRights over DOMAIN.LOCAL"),
        ]
        steps = plan_ad_chain(findings).ordered()
        assert steps[0].technique == "DCSYNC"
        assert steps[1].technique == "KERBEROAST"

    def test_full_priority_order(self):
        findings = [
            _f("ACL: GenericAll over jdoe"),          # acl-abuse (70)
            _f("Kerberoastable account: svc"),        # 60
            _f("AS-REP roastable account: guest"),    # 50
            _f("Unconstrained delegation: WS01"),     # 30
            _f("ADCS ESC1 on template UserCert"),     # 20
            _f("ACL: GetChanges over corp.local"),    # dcsync 10
        ]
        techs = [s.technique for s in plan_ad_chain(findings).ordered()]
        assert techs[0] == "DCSYNC"
        assert techs[1] == "ESC1"
        assert techs[2] == "UNCONSTRAINED"
        assert techs[-1].startswith("ACL-")


class TestTechniqueMapping:
    def test_esc_carries_exploit(self):
        f = _f("ADCS ESC1 on template UserCert", exploit="certipy req ...")
        step = plan_ad_chain([f]).ordered()[0]
        assert step.technique == "ESC1" and step.command == "certipy req ..."

    def test_rbcd_for_computer_target(self):
        f = _f("ACL: GenericWrite over WEB01$")
        step = plan_ad_chain([f]).ordered()[0]
        assert step.technique == "RBCD"

    def test_generic_write_over_user_is_acl_abuse(self):
        f = _f("ACL: GenericWrite over alice")
        step = plan_ad_chain([f]).ordered()[0]
        assert step.technique.startswith("ACL-")

    def test_dangling_template_included(self):
        f = _f("Dangling ADCS template reference: OldWeb")
        step = plan_ad_chain([f]).ordered()[0]
        assert step.technique == "ADCS-DANGLING"


class TestRender:
    def test_empty(self):
        assert "no AD attack primitives" in render_chain(plan_ad_chain([]))[0]

    def test_creds_gate_shown(self):
        f = _f("Kerberoastable account: svc")
        lines = render_chain(plan_ad_chain([f]), have_creds=False)
        assert any("needs a domain credential" in ln for ln in lines)

    def test_no_gate_with_creds(self):
        f = _f("Kerberoastable account: svc")
        lines = render_chain(plan_ad_chain([f], have_creds=True), have_creds=True)
        assert not any("needs a domain credential" in ln for ln in lines)

    def test_asrep_never_gated(self):
        f = _f("AS-REP roastable account: guest")
        lines = render_chain(plan_ad_chain([f]), have_creds=False)
        assert not any("needs a domain credential" in ln for ln in lines)
