"""Auto-foothold modules + orchestrator auto-foothold + cap_setuid escalation."""

import asyncio

from breachload.analysis.privesc_auto import attempt_escalation
from breachload.core.config import EngagementConfig
from breachload.core.orchestrator import Orchestrator
from breachload.core.session import WebshellSession
from breachload.core.state import EngagementState, Finding, Phase, Severity
from breachload.exploit.footholds import (
    FreepbxFoothold,
    GlpiHtmlawedFoothold,
    MetabaseFoothold,
    OfbizGroovyFoothold,
    foothold_for,
)
from breachload.safety.audit import AuditLog
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator
from breachload.tools.registry import allowed_binaries, default_registry


class TestFootholdRegistry:
    def test_freepbx_registered(self):
        m = foothold_for("CVE-2025-57819")
        assert isinstance(m, FreepbxFoothold)

    def test_glpi_registered(self):
        assert isinstance(foothold_for("CVE-2022-35914"), GlpiHtmlawedFoothold)

    def test_ofbiz_registered(self):
        assert isinstance(foothold_for("CVE-2023-51467"), OfbizGroovyFoothold)

    def test_metabase_registered(self):
        assert isinstance(foothold_for("CVE-2023-38646"), MetabaseFoothold)

    def test_unknown_cve(self):
        assert foothold_for("CVE-0000-0000") is None


class TestOfbizEstablish:
    def test_establishes_webshell(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            if "bl-shell.jsp" in argv[-1] and "cmd=" in argv[-1]:
                return 0, "uid=0(root)", ""
            return 0, "", ""

        sess = OfbizGroovyFoothold().establish("10.10.11.9", 443, runner=runner,
                                               sleeper=lambda s: None)
        assert sess is not None and "bl-shell.jsp?cmd=FUZZ" in sess.template
        # The drop request went through ProgramExport with requirePasswordChange=Y.
        assert any("requirePasswordChange=Y" in tok for a in calls for tok in a)
        assert any("groovyProgram=" in tok for a in calls for tok in a)


class TestMetabaseEstablish:
    def test_needs_setup_token(self):
        # /api/session/properties returns nothing useful -> no session.
        sess = MetabaseFoothold().establish("10.10.11.9", 3000,
                                            runner=lambda a, t: (0, "{}", ""),
                                            sleeper=lambda s: None)
        assert sess is None

    def test_establishes_webshell(self):
        def runner(argv, timeout):
            url = argv[-1]
            if url.endswith("/api/session/properties"):
                return 0, '{"setup-token":"deadbeef-token"}', ""
            if "/tmp/shell.php" in url and "cmd=" in url:
                return 0, "uid=999(metabase)", ""
            return 0, "", ""

        sess = MetabaseFoothold().establish("10.10.11.9", 3000, runner=runner,
                                            sleeper=lambda s: None)
        assert sess is not None and "/tmp/shell.php?cmd=FUZZ" in sess.template


class TestGlpiEstablish:
    def test_establishes_webshell_session(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            if "shell.php" in argv[-1]:
                return 0, "uid=33(www-data) gid=33(www-data)", ""
            return 0, "", ""

        sess = GlpiHtmlawedFoothold().establish("10.10.10.7", 80, runner=runner,
                                                sleeper=lambda s: None)
        assert isinstance(sess, WebshellSession)
        assert "vendor/htmlawed/htmlawed/shell.php?cmd=FUZZ" in sess.template
        assert any("htmLawedTest.php" in tok for a in calls for tok in a)
        assert any("hhook=system" in tok for a in calls for tok in a)

    def test_returns_none_when_shell_never_appears(self):
        sess = GlpiHtmlawedFoothold().establish("10.10.10.7", 80, attempts=2,
                                                runner=lambda argv, t: (0, "", ""),
                                                sleeper=lambda s: None)
        assert sess is None


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
        # foothold established -> session set -> POST privesc rooted via docker,
        # and the session was upgraded to a persistent root channel.
        from breachload.core.session import RootSession
        assert isinstance(orch.session, RootSession) and orch.session.base is sess
        assert "b17c258e4fe967463a10b09c5e72102b" in state.flags
        fmod._MODULES[:] = [fmod.FreepbxFoothold()]   # restore
