"""Foothold session + autonomous session-driven privesc."""

import asyncio

from breachload.analysis.privesc_auto import attempt_escalation, run_enum
from breachload.core.config import EngagementConfig
from breachload.core.orchestrator import Orchestrator
from breachload.core.session import SshSession, WebshellSession
from breachload.core.state import EngagementState, Phase
from breachload.safety.audit import AuditLog
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator
from breachload.tools.registry import allowed_binaries, default_registry


class TestSessionSpecs:
    def test_webshell_from_spec(self):
        s = WebshellSession.from_spec("http://10.10.10.5/shell.php?cmd=FUZZ")
        assert s.host == "10.10.10.5"
        argv = s._argv("id; whoami")
        # command is URL-encoded into the URL (no raw shell metachars in the argv)
        assert argv[0] == "curl"
        assert "%3B" in argv[-1] and "FUZZ" not in argv[-1]

    def test_webshell_requires_fuzz(self):
        import pytest
        with pytest.raises(ValueError):
            WebshellSession.from_spec("http://x/shell.php?cmd=")

    def test_ssh_from_spec(self):
        s = SshSession.from_spec("bob:pw@10.10.10.5:2222")
        assert s.host == "10.10.10.5" and s.user == "bob" and s.port == 2222
        assert s._argv("id")[0] == "sshpass"

    def test_run_uses_runner(self):
        s = WebshellSession.from_spec("http://h/s.php?cmd=FUZZ")
        out = s.run("id", runner=lambda argv, timeout: (0, "uid=999(asterisk)", ""))
        assert "asterisk" in out

    def test_roundtrip_dict(self):
        from breachload.core.session import Session
        s = SshSession.from_spec("a:b@h")
        assert Session.from_dict(s.to_dict()).user == "a"


class TestRunEnum:
    def test_parses_session_output(self):
        outputs = {
            "id": "uid=1000(bob) groups=1000(bob),998(docker)",
            "sudo -n -l 2>/dev/null": "(ALL) NOPASSWD: /usr/bin/find",
        }

        def runner(argv, timeout):
            # webshell argv: last token is the URL with the encoded command
            for cmd, out in outputs.items():
                from urllib.parse import quote
                if quote(cmd, safe="") in argv[-1]:
                    return 0, out, ""
            return 0, "", ""

        s = WebshellSession.from_spec("http://h/s.php?cmd=FUZZ")
        # bind the runner via a wrapper
        orig = s.run
        s.run = lambda cmd, **k: orig(cmd, runner=runner)
        findings, creds, raw = run_enum(s)
        assert "docker" in raw
        assert any("docker" in f.title.lower() for f in findings)


class TestEscalation:
    def _sess(self, responses):
        s = WebshellSession.from_spec("http://h/s.php?cmd=FUZZ")

        def run(command, **k):
            for needle, out in responses.items():
                if needle in command:
                    return out
            return ""
        s.run = run
        return s

    def test_full_sudo_reads_root_flag(self):
        s = self._sess({"sudo cat /root/root.txt": "d41d8cd98f00b204e9800998ecf8427e"})
        r = attempt_escalation(s, "(ALL : ALL) ALL", [])
        assert r.escalated and r.root_flag == "d41d8cd98f00b204e9800998ecf8427e"
        assert "full sudo" in r.method

    def test_docker_group(self):
        s = self._sess({"docker run": "a" * 32})
        r = attempt_escalation(s, "uid=1000(bob) groups=998(docker)", [])
        assert r.escalated and "docker" in r.method

    def test_sudo_nopasswd_binary(self):
        s = self._sess({"sudo bash": "cafebabecafebabecafebabecafebabe"})
        r = attempt_escalation(s, "(root) NOPASSWD: /bin/bash", [])
        assert r.escalated and "bash" in r.method

    def test_no_vector(self):
        s = self._sess({})
        r = attempt_escalation(s, "uid=1000(bob) groups=1000(bob)", [])
        assert not r.escalated


class TestOrchestratorPost:
    def test_autonomous_privesc_in_post_phase(self, tmp_path):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"],
                               auto_exploit=True, authorized=True)
        state = EngagementState(name="t", phase=Phase.POST)
        reg = default_registry()

        class _Planner:
            online = False

            def next_action(self, *a, **k):
                from breachload.core.llm import Plan
                return Plan("phase_complete", rationale="done")

        sess = WebshellSession.from_spec("http://10.10.10.5/s.php?cmd=FUZZ")

        def run(command, **k):
            if command == "id":
                return "uid=1000(bob) groups=998(docker)"
            if "docker run" in command:
                return "b17c258e4fe967463a10b09c5e72102b"
            return ""
        sess.run = run

        orch = Orchestrator(cfg, state, reg,
                            Validator(Scope.from_config(cfg.targets), allowed_binaries(reg),
                                      Risk.EXPLOIT),
                            _Planner(), AuditLog(tmp_path / "a.jsonl"), tmp_path / "s.json",
                            auto_exploit=True, session=sess)
        asyncio.run(orch.run_engagement(stop_after=Phase.POST))
        assert "b17c258e4fe967463a10b09c5e72102b" in state.flags
        assert any("root via" in f.title.lower() for f in state.findings)

    def test_out_of_scope_session_refused(self, tmp_path):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"],
                               auto_exploit=True, authorized=True)
        state = EngagementState(name="t", phase=Phase.POST)
        reg = default_registry()

        class _P:
            online = False

            def next_action(self, *a, **k):
                from breachload.core.llm import Plan
                return Plan("phase_complete")

        sess = WebshellSession.from_spec("http://10.99.99.99/s.php?cmd=FUZZ")
        sess.run = lambda c, **k: "d41d8cd98f00b204e9800998ecf8427e"
        orch = Orchestrator(cfg, state, reg,
                            Validator(Scope.from_config(cfg.targets), allowed_binaries(reg),
                                      Risk.EXPLOIT),
                            _P(), AuditLog(tmp_path / "a.jsonl"), tmp_path / "s.json",
                            auto_exploit=True, session=sess)
        asyncio.run(orch.run_engagement(stop_after=Phase.POST))
        assert not state.flags   # off-scope session must not run


class TestSuidEscalation:
    def _sess(self, responses):
        s = WebshellSession.from_spec("http://h/s.php?cmd=FUZZ")

        def run(command, **k):
            for needle, out in responses.items():
                if needle in command:
                    return out
            return ""
        s.run = run
        return s

    def test_suid_shell_reads_root(self):
        s = self._sess({"/usr/bin/bash -p": "d41d8cd98f00b204e9800998ecf8427e"})
        enum = "uid=1000(bob) groups=1000(bob)\n/usr/bin/bash\n/usr/bin/passwd\n"
        r = attempt_escalation(s, enum, [])
        assert r.escalated and "SUID bash" in r.method

    def test_non_shell_suid_ignored(self):
        s = self._sess({"passwd": "x" * 32})
        enum = "/usr/bin/passwd\n/usr/bin/sudo\n"
        r = attempt_escalation(s, enum, [])
        assert not r.escalated
