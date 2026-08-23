"""Auto-exploit authorization gate, phase walk, and CLI wiring."""

import json

from typer.testing import CliRunner

import breachload.cli as climod
from breachload.core.authz import (
    Operator,
    authorize_operator,
    gate_auto_exploit,
    load_operators,
)
from breachload.core.config import EngagementConfig
from breachload.core.orchestrator import AUTO_EXPLOIT_ORDER, Orchestrator
from breachload.core.state import EngagementState, Phase

runner = CliRunner()

_OPS = [Operator(id="alice", token="s3cr3t-token", note="lead")]


class TestAuthorizeOperator:
    def test_authorized(self):
        d = authorize_operator(_OPS, operator_id="alice", token="s3cr3t-token")
        assert d.authorized and d.operator == "alice"

    def test_wrong_token(self):
        d = authorize_operator(_OPS, operator_id="alice", token="nope")
        assert not d.authorized and "token" in d.reason

    def test_unknown_operator(self):
        d = authorize_operator(_OPS, operator_id="mallory", token="x")
        assert not d.authorized and "not authorized" in d.reason

    def test_no_operators_file(self):
        d = authorize_operator([], operator_id="alice", token="x")
        assert not d.authorized and "no operators" in d.reason

    def test_missing_env(self):
        d = authorize_operator(_OPS, operator_id=None, token=None)
        assert not d.authorized and "identify" in d.reason


class TestLoadOperators:
    def test_reads_file(self, tmp_path):
        p = tmp_path / "ops.json"
        p.write_text(json.dumps({"operators": [{"id": "a", "token": "t"}]}), encoding="utf-8")
        ops = load_operators(p)
        assert len(ops) == 1 and ops[0].id == "a"

    def test_missing_file_is_empty(self, tmp_path):
        assert load_operators(tmp_path / "nope.json") == []


class TestGate:
    def test_requires_auto_exploit_flag(self):
        cfg = EngagementConfig(name="t", authorized=True, auto_exploit=False)
        assert not gate_auto_exploit(cfg, _OPS).authorized

    def test_requires_authorized_flag(self):
        cfg = EngagementConfig(name="t", authorized=False, auto_exploit=True)
        d = gate_auto_exploit(cfg, _OPS)
        assert not d.authorized and "authorized" in d.reason

    def test_passes_with_all_conditions(self, monkeypatch):
        monkeypatch.setenv("BREACHLOAD_OPERATOR", "alice")
        monkeypatch.setenv("BREACHLOAD_TOKEN", "s3cr3t-token")
        cfg = EngagementConfig(name="t", authorized=True, auto_exploit=True)
        assert gate_auto_exploit(cfg, _OPS).authorized


class TestPhaseWalk:
    def test_auto_exploit_order_includes_exploit_and_post(self):
        assert Phase.EXPLOIT in AUTO_EXPLOIT_ORDER and Phase.POST in AUTO_EXPLOIT_ORDER

    def test_orchestrator_walks_to_post(self, tmp_path):
        import asyncio

        from breachload.safety.audit import AuditLog
        from breachload.safety.scope import Scope
        from breachload.safety.validator import Risk, Validator
        from breachload.tools.registry import allowed_binaries, default_registry

        cfg = EngagementConfig(name="t", targets=["10.10.10.5"],
                               auto_exploit=True, authorized=True)
        state = EngagementState(name="t")
        reg = default_registry()

        class _Planner:
            online = False

            def next_action(self, *a, **k):
                from breachload.core.llm import Plan
                return Plan("phase_complete", rationale="done")

        orch = Orchestrator(cfg, state, reg,
                            Validator(Scope.from_config(cfg.targets), allowed_binaries(reg),
                                      Risk.EXPLOIT),
                            _Planner(), AuditLog(tmp_path / "a.jsonl"), tmp_path / "s.json",
                            auto_exploit=True)
        asyncio.run(orch.run_engagement(stop_after=Phase.POST))
        assert state.phase == Phase.POST


class TestHistoryPrune:
    def _orch(self, tmp_path, state):
        from breachload.safety.audit import AuditLog
        from breachload.safety.scope import Scope
        from breachload.safety.validator import Risk, Validator
        from breachload.tools.registry import allowed_binaries, default_registry
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"])
        reg = default_registry()

        class _Planner:
            online = False

            def next_action(self, *a, **k):
                from breachload.core.llm import Plan
                return Plan("phase_complete", rationale="done")

        return Orchestrator(cfg, state, reg,
                            Validator(Scope.from_config(cfg.targets), allowed_binaries(reg),
                                      Risk.ACTIVE),
                            _Planner(), AuditLog(tmp_path / "a.jsonl"), tmp_path / "s.json")

    def test_blocked_actions_pruned_executed_kept(self, tmp_path):
        import asyncio

        from breachload.core.state import ActionRecord, Phase
        state = EngagementState(name="t")
        state.history = [
            ActionRecord(phase=Phase.ENUM, tool="whatweb", command=["whatweb", "in-scope"],
                         approved=True, exit_code=0),                       # executed - keep
            ActionRecord(phase=Phase.ENUM, tool="whatweb", command=["whatweb", "vhost.htb"],
                         approved=False, exit_code=None),                   # blocked - drop
            ActionRecord(phase=Phase.ENUM, tool="ffuf", command=["ffuf", "bad"],
                         approved=False, exit_code=-1),                     # build-fail - keep
        ]
        orch = self._orch(tmp_path, state)
        asyncio.run(orch.run_engagement(stop_after=Phase.VULN))
        tools_targets = [(a.tool, a.command[-1]) for a in state.history]
        assert ("whatweb", "in-scope") in tools_targets       # executed kept
        assert ("ffuf", "bad") in tools_targets               # build-failure kept
        assert ("whatweb", "vhost.htb") not in tools_targets  # blocked pruned -> retryable


class TestCli:
    def _cfg(self, tmp_path, **extra):
        lines = "name: t\ntargets: ['10.10.10.5']\n"
        for k, v in extra.items():
            lines += f"{k}: {v}\n"
        p = tmp_path / "t.yaml"
        p.write_text(lines, encoding="utf-8")
        return p

    def test_refuses_without_authorization(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        cfg = self._cfg(tmp_path)   # no auto_exploit / authorized
        result = runner.invoke(climod.app, ["auto-exploit", str(cfg), "--yes"])
        assert result.exit_code == 2
        assert "refused" in result.output

    def test_runs_when_authorized(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        ops = tmp_path / "ops.json"
        ops.write_text(json.dumps({"operators": [{"id": "alice", "token": "t"}]}),
                       encoding="utf-8")
        monkeypatch.setenv("BREACHLOAD_OPERATORS", str(ops))
        monkeypatch.setenv("BREACHLOAD_OPERATOR", "alice")
        monkeypatch.setenv("BREACHLOAD_TOKEN", "t")

        async def _noop(self, *a, **k):
            self.state.upsert_host("10.10.10.5")

        monkeypatch.setattr(climod.Orchestrator, "run_engagement", _noop)
        cfg = self._cfg(tmp_path, auto_exploit="true", authorized="true")
        result = runner.invoke(climod.app, ["auto-exploit", str(cfg), "--yes"])
        assert result.exit_code == 0, result.output
        assert "AUTO-EXPLOIT MODE" in result.output and "alice" in result.output
