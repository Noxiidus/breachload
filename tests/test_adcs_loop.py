"""Autonomous ADCS ESC1 loop in the orchestrator (POST phase, auto-exploit)."""

from breachload.core.config import EngagementConfig
from breachload.core.llm import Planner
from breachload.core.orchestrator import Orchestrator
from breachload.core.state import (
    Credential,
    EngagementState,
    Finding,
    Phase,
    Severity,
)
from breachload.safety.audit import AuditLog
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator
from breachload.tools.registry import allowed_binaries, default_registry


def _orch(tmp_path, state):
    reg = default_registry()
    scope = Scope.from_config(["10.10.11.0/24"])
    validator = Validator(scope, allowed_binaries(reg), Risk.EXPLOIT)
    cfg = EngagementConfig(name="t", targets=["10.10.11.0/24"],
                           auto_exploit=True, authorized=True)
    return Orchestrator(cfg, state, reg, validator, Planner(config=cfg),
                        AuditLog(tmp_path / "audit.jsonl"),
                        tmp_path / "state.json")


def _state_with_dc_cred_esc1():
    st = EngagementState(name="t", phase=Phase.POST)
    dc = st.upsert_host("10.10.11.5")
    dc.tags.extend(["dc", "domain:corp.local"])
    st.credentials.append(Credential(username="bob", secret="Password1",
                                     kind="password", validated=True))
    st.add_finding(Finding(
        title="ADCS ESC1 on template UserCert",
        severity=Severity.CRITICAL, host="10.10.11.5"))
    return st


class TestAdcsLoop:
    def test_fires_certipy_req_and_confirms_on_success(self, tmp_path):
        st = _state_with_dc_cred_esc1()
        orch = _orch(tmp_path, st)
        orch._autonomous_adcs(runner=lambda argv, t: (
            0, "Saved certificate to administrator.pfx", ""))
        confirmed = [f for f in st.findings if "successful" in f.title.lower()]
        assert confirmed and confirmed[0].validation == "confirmed"

    def test_command_uses_template_from_finding(self, tmp_path):
        st = _state_with_dc_cred_esc1()
        orch = _orch(tmp_path, st)
        seen = {}

        def runner(argv, t):
            seen["argv"] = argv
            return 0, "", ""

        orch._autonomous_adcs(runner=runner)
        assert "UserCert" in " ".join(seen["argv"])
        assert "administrator@corp.local" in " ".join(seen["argv"])

    def test_noop_without_esc_finding(self, tmp_path):
        st = EngagementState(name="t", phase=Phase.POST)
        dc = st.upsert_host("10.10.11.5")
        dc.tags.extend(["dc", "domain:corp.local"])
        st.credentials.append(Credential(username="bob", secret="pw",
                                         kind="password", validated=True))
        orch = _orch(tmp_path, st)
        called = {"n": 0}

        def runner(argv, t):
            called["n"] += 1
            return 0, "", ""

        orch._autonomous_adcs(runner=runner)
        assert called["n"] == 0

    def test_noop_without_dc(self, tmp_path):
        st = EngagementState(name="t", phase=Phase.POST)
        st.credentials.append(Credential(username="bob", secret="pw",
                                         kind="password"))
        st.add_finding(Finding(title="ADCS ESC1 on template UserCert",
                               severity=Severity.CRITICAL))
        orch = _orch(tmp_path, st)
        called = {"n": 0}

        def runner(argv, t):
            called["n"] += 1
            return 0, "", ""

        orch._autonomous_adcs(runner=runner)
        assert called["n"] == 0

    def test_out_of_scope_dc_refused(self, tmp_path):
        st = EngagementState(name="t", phase=Phase.POST)
        dc = st.upsert_host("192.168.1.5")
        dc.tags.extend(["dc", "domain:corp.local"])
        st.credentials.append(Credential(username="bob", secret="pw",
                                         kind="password"))
        st.add_finding(Finding(title="ADCS ESC1 on template UserCert",
                               severity=Severity.CRITICAL))
        orch = _orch(tmp_path, st)
        called = {"n": 0}

        def runner(argv, t):
            called["n"] += 1
            return 0, "", ""

        orch._autonomous_adcs(runner=runner)
        assert called["n"] == 0
