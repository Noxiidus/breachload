"""Autonomous Kerberoast loop in the orchestrator (POST phase, auto-exploit)."""

from breachload.core.config import EngagementConfig
from breachload.core.orchestrator import Orchestrator
from breachload.core.state import Credential, EngagementState, Phase
from breachload.safety.audit import AuditLog
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator
from breachload.tools.registry import allowed_binaries, default_registry

_TGS = "$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc~db*$aaaa$bbbb\n"


def _orch(tmp_path, state):
    reg = default_registry()
    scope = Scope.from_config(["10.10.11.0/24"])
    validator = Validator(scope, allowed_binaries(reg), Risk.EXPLOIT)
    cfg = EngagementConfig(name="t", targets=["10.10.11.0/24"],
                           auto_exploit=True, authorized=True)
    from breachload.core.llm import Planner
    return Orchestrator(cfg, state, reg, validator, Planner(config=cfg),
                        AuditLog(tmp_path / "audit.jsonl"), tmp_path / "state.json")


def _state_with_dc_and_cred():
    st = EngagementState(name="t", phase=Phase.POST)
    dc = st.upsert_host("10.10.11.5")
    dc.tags.extend(["dc", "domain:corp.local"])
    st.credentials.append(Credential(username="bob", secret="Password1",
                                     kind="password", validated=True))
    return st


class TestKerberoastLoop:
    def test_roasts_and_stores_hashes(self, tmp_path):
        st = _state_with_dc_and_cred()
        orch = _orch(tmp_path, st)
        orch._autonomous_kerberoast(runner=lambda argv, t: (0, _TGS, ""))
        # The recovered TGS hash landed as a kind=hash credential + a finding.
        assert any(c.kind == "hash" and "krb5tgs" in (c.secret or "")
                   for c in st.credentials)
        assert any("Kerberoastable" in f.title for f in st.findings)

    def test_command_targets_the_dc(self, tmp_path):
        st = _state_with_dc_and_cred()
        orch = _orch(tmp_path, st)
        seen = {}

        def runner(argv, t):
            seen["argv"] = argv
            return 0, "", ""

        orch._autonomous_kerberoast(runner=runner)
        joined = " ".join(seen["argv"])
        assert "corp.local/bob:Password1" in joined and "10.10.11.5" in joined

    def test_noop_without_dc(self, tmp_path):
        st = EngagementState(name="t", phase=Phase.POST)
        st.credentials.append(Credential(username="bob", secret="x", kind="password"))
        orch = _orch(tmp_path, st)
        called = {"n": 0}

        def runner(argv, t):
            called["n"] += 1
            return 0, "", ""

        orch._autonomous_kerberoast(runner=runner)
        assert called["n"] == 0    # never ran a command

    def test_noop_without_credential(self, tmp_path):
        st = EngagementState(name="t", phase=Phase.POST)
        st.upsert_host("10.10.11.5").tags.extend(["dc", "domain:corp.local"])
        orch = _orch(tmp_path, st)
        called = {"n": 0}

        def runner(argv, t):
            called["n"] += 1
            return 0, "", ""

        orch._autonomous_kerberoast(runner=runner)
        assert called["n"] == 0

    def test_out_of_scope_dc_refused(self, tmp_path):
        st = EngagementState(name="t", phase=Phase.POST)
        st.upsert_host("192.168.1.5").tags.extend(["dc", "domain:corp.local"])
        st.credentials.append(Credential(username="bob", secret="x", kind="password"))
        orch = _orch(tmp_path, st)
        called = {"n": 0}

        def runner(argv, t):
            called["n"] += 1
            return 0, "", ""

        orch._autonomous_kerberoast(runner=runner)
        assert called["n"] == 0    # 192.168.x is out of scope
