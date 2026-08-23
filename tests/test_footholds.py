"""Auto-foothold modules + orchestrator auto-foothold + cap_setuid escalation."""

import asyncio

from breachload.analysis.privesc_auto import attempt_escalation
from breachload.core.config import EngagementConfig
from breachload.core.orchestrator import Orchestrator
from breachload.core.session import WebshellSession
from breachload.core.state import EngagementState, Finding, Phase, Severity
from breachload.exploit.footholds import FreepbxFoothold, foothold_for
from breachload.safety.audit import AuditLog
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator
from breachload.tools.registry import allowed_binaries, default_registry


class TestFootholdRegistry:
    def test_freepbx_registered(self):
        m = foothold_for("CVE-2025-57819")
        assert isinstance(m, FreepbxFoothold)

    def test_unknown_cve(self):
        assert foothold_for("CVE-0000-0000") is None


class TestFreepbxEstablish:
    def test_establishes_webshell_session(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            url = argv[-1]
            if "shell.php" in url:
                return 0, "uid=999(asterisk) gid=1000(asterisk)", ""
            return 0, "", ""   # the SQLi drop

        sess = FreepbxFoothold().establish("10.10.10.5", 80, runner=runner,
                                           sleeper=lambda s: None)
        assert isinstance(sess, WebshellSession)
        assert sess.host == "10.10.10.5" and "shell.php?cmd=FUZZ" in sess.template
        # the first call fired the stacked-query SQLi drop
        assert any("ajax.php" in tok for a in calls for tok in a)
        assert any("cron_jobs" in tok for a in calls for tok in a)   # the webshell dropper

    def test_returns_none_when_shell_never_appears(self):
        sess = FreepbxFoothold().establish("10.10.10.5", 80, attempts=2,
                                           runner=lambda argv, t: (0, "", ""),
                                           sleeper=lambda s: None)
        assert sess is None


class TestCapSetuidEscalation:
    def test_cap_setuid_python_reads_root(self):
        s = WebshellSession.from_spec("http://h/s.php?cmd=FUZZ")

        def run(command, **k):
            if "setuid(0)" in command and "python" in command:
                return "d41d8cd98f00b204e9800998ecf8427e"
            return ""
        s.run = run
        enum = "uid=1000(bob) groups=1000(bob)\n/usr/bin/python3.9 = cap_setuid+ep\n"
        r = attempt_escalation(s, enum, [])
        assert r.escalated and "cap_setuid" in r.method and "python" in r.method


class TestOrchestratorAutoFoothold:
    def test_auto_foothold_then_privesc(self, tmp_path):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"],
                               auto_exploit=True, authorized=True)
        state = EngagementState(name="t", phase=Phase.EXPLOIT)
        state.upsert_host("10.10.10.5")
        state.add_finding(Finding(title="FreePBX SQLi (CVE-2025-57819)", host="10.10.10.5",
                                  service_key="80/tcp", severity=Severity.CRITICAL,
                                  cve=["CVE-2025-57819"]))
        reg = default_registry()

        class _P:
            online = False

            def next_action(self, *a, **k):
                from breachload.core.llm import Plan
                return Plan("phase_complete")

        # Patch the foothold module + session so no network happens.
        import breachload.exploit.footholds as fmod
        sess = WebshellSession.from_spec("http://10.10.10.5/shell.php?cmd=FUZZ")

        def sess_run(command, **k):
            if command == "id":
                return "uid=1000(bob) groups=998(docker)"
            if "docker run" in command:
                return "b17c258e4fe967463a10b09c5e72102b"
            return ""
        sess.run = sess_run

        class _Fake(fmod.FreepbxFoothold):
            def establish(self, target, port=80, **k):
                return sess

        fmod._MODULES[:] = [_Fake()]

        orch = Orchestrator(cfg, state, reg,
                            Validator(Scope.from_config(cfg.targets), allowed_binaries(reg),
                                      Risk.EXPLOIT),
                            _P(), AuditLog(tmp_path / "a.jsonl"), tmp_path / "s.json",
                            auto_exploit=True)
        asyncio.run(orch.run_engagement(stop_after=Phase.POST))
        # foothold established -> session set -> POST privesc rooted via docker
        assert orch.session is sess
        assert "b17c258e4fe967463a10b09c5e72102b" in state.flags
        fmod._MODULES[:] = [fmod.FreepbxFoothold()]   # restore
