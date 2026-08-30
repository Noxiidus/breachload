"""Session.upload() — base64 channel + native overrides + auto-staging."""

from breachload.analysis.winprivesc_auto import _parse_enum, attempt_win_escalation
from breachload.core.session import SshSession, WebshellSession, WinrmSession


def _make_file(tmp_path, data=b"MZ\x90\x00binary"):
    p = tmp_path / "PrintSpoofer.exe"
    p.write_bytes(data)
    return str(p)


class _RecordingSession(WebshellSession):
    """A webshell session that records commands and fakes remote state."""
    def run(self, command, *, timeout=30.0, runner=None):
        self._log = getattr(self, "_log", [])
        self._log.append(command)
        if "test -s" in command:
            return "OK"
        return ""


class TestWebshellUpload:
    def test_base64_channel_uploads(self, tmp_path):
        local = _make_file(tmp_path)
        s = _RecordingSession(host="h", template="http://h/shell.php?cmd=FUZZ")
        assert s.upload(local, "/tmp/ps.exe") is True
        joined = "\n".join(s._log)
        assert ".b64" in joined and "base64 -d" in joined
        assert "test -s /tmp/ps.exe" in joined

    def test_missing_local_file_returns_false(self):
        s = _RecordingSession(host="h", template="http://h/shell.php?cmd=FUZZ")
        assert s.upload("/does/not/exist", "/tmp/x") is False


class TestSshUploadNative:
    def test_scp_used_first(self, tmp_path):
        local = _make_file(tmp_path)
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            return 0, "", ""     # scp succeeds

        s = SshSession(host="h", user="bob", password="pw")
        assert s.upload(local, "/tmp/ps.exe", runner=runner) is True
        assert any(a[0] in ("scp", "sshpass") for a in calls)

    def test_falls_back_to_base64_on_scp_failure(self, tmp_path):
        local = _make_file(tmp_path)

        def runner(argv, timeout):
            if "scp" in argv:
                return 1, "", "conn refused"      # scp fails
            if "test -s" in " ".join(argv):
                return 0, "OK", ""                # base64 fallback verify succeeds
            return 0, "", ""

        s = SshSession(host="h", user="bob", password="pw")
        assert s.upload(local, "/tmp/ps.exe", runner=runner) is True


class TestWinrmUpload:
    def test_powershell_base64_write(self, tmp_path):
        local = _make_file(tmp_path)
        log = []

        def runner(argv, timeout):
            log.append(argv)
            if "Test-Path" in " ".join(argv):
                return 0, "OK", ""
            return 0, "", ""

        s = WinrmSession(host="h", user="a", password="b")
        assert s.upload(local, "C:\\Windows\\Temp\\ps.exe", runner=runner) is True
        text = "\n".join(" ".join(a) for a in log)
        assert "FromBase64String" in text and "WriteAllBytes" in text


class TestAutoStaging:
    def test_escalation_stages_printspoofer(self, tmp_path):
        local = _make_file(tmp_path)
        uploaded = {}

        class _S(WinrmSession):
            def upload(self, lp, rp, *, timeout=180.0, runner=None):
                uploaded["local"] = lp
                uploaded["remote"] = rp
                return True

            def run(self, command, *, timeout=30.0, runner=None):
                # After staging, PrintSpoofer "reads" the flag.
                if "PrintSpoofer" in command:
                    return "deadbeefdeadbeefdeadbeefdeadbeef"
                return ""

        enum = _parse_enum({"whoami": "SeImpersonatePrivilege ... Enabled"})
        s = _S(host="h", user="a", password="b")
        res = attempt_win_escalation(s, enum, tool_paths={"printspoofer": local})
        assert res.escalated
        assert uploaded["local"] == local
        assert "PrintSpoofer.exe" in uploaded["remote"]

    def test_no_path_no_staging(self):
        # Without a configured tool path, no upload is attempted (best effort run).
        class _S(WinrmSession):
            def upload(self, *a, **k):   # pragma: no cover - must not be called
                raise AssertionError("should not upload without a tool path")

            def run(self, command, *, timeout=30.0, runner=None):
                return ""

        enum = _parse_enum({"whoami": "SeImpersonatePrivilege ... Enabled"})
        res = attempt_win_escalation(_S(host="h", user="a", password="b"), enum)
        assert not res.escalated
