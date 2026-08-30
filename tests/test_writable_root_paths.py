"""Generalized 'root reads a file I can write' privesc detector (class, not per-box)."""

from breachload.analysis.writable_root_paths import find_writable_root_exec

# A realistic enum blob in the run_enum "$ cmd\noutput" format.
_ENUM = """$ id
uid=999(app) gid=999(app)
$ find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys|dev|run)' | head -60
/etc/dahdi/init.conf
/opt/app/config/settings.py
/tmp/junk
$ cat /etc/systemd/system/*.service /lib/systemd/system/*.service 2>/dev/null | grep -iE 'ExecStart' | head -60
ExecStart=/usr/sbin/dahdi_cfg -c /etc/dahdi/system.conf
ExecStart=-/opt/app/bin/run.sh
$ cat /etc/init.d/* 2>/dev/null | grep -E '(^|[[:space:]])(\\.|source)[[:space:]]+/' | head -40
[ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf
$ cat /etc/cron.d/* /var/spool/cron/crontabs/* /etc/crontab 2>/dev/null | grep -vE '^[[:space:]]*#' | head -60
*/5 * * * * root /opt/scripts/backup.sh
"""


class TestDetector:
    def test_detects_init_sourced_writable(self):
        findings = find_writable_root_exec(_ENUM)
        titles = [f.title for f in findings]
        assert any("/etc/dahdi/init.conf" in t for t in titles)
        f = next(f for f in findings if "/etc/dahdi/init.conf" in f.title)
        assert f.severity.value == "high"
        assert "init-script source" in f.evidence

    def test_ignores_non_writable_root_paths(self):
        # /usr/sbin/dahdi_cfg is root-referenced but NOT in the writable set.
        findings = find_writable_root_exec(_ENUM)
        assert not any("dahdi_cfg" in f.title for f in findings)

    def test_ignores_writable_non_referenced(self):
        # /tmp/junk is writable but nothing root references it (and /tmp is noise).
        findings = find_writable_root_exec(_ENUM)
        assert not any("/tmp/junk" in f.title for f in findings)

    def test_systemd_execstart_writable(self):
        enum = ("$ find / -writable -type f 2>/dev/null\n/opt/app/bin/run.sh\n"
                "$ cat /etc/systemd/system/*.service ExecStart\n"
                "ExecStart=-/opt/app/bin/run.sh\n")
        findings = find_writable_root_exec(enum)
        assert any("/opt/app/bin/run.sh" in f.title for f in findings)
        assert "systemd ExecStart" in findings[0].evidence

    def test_cron_command_writable(self):
        enum = ("$ find / -writable -type f\n/opt/scripts/backup.sh\n"
                "$ cat /etc/cron.d/* crontab\n*/5 * * * * root /opt/scripts/backup.sh\n")
        findings = find_writable_root_exec(enum)
        assert any("/opt/scripts/backup.sh" in f.title for f in findings)

    def test_empty(self):
        assert find_writable_root_exec("") == []

    def test_exploit_primitive_present(self):
        f = find_writable_root_exec(_ENUM)[0]
        assert "rootbash" in f.exploit and f.remediation


class TestWiredIntoEnum:
    def test_run_enum_includes_class_findings(self):
        # A fake session that replays the writable + init blocks for the two commands.
        from breachload.analysis.privesc_auto import run_enum

        class _S:
            host = "10.10.10.5"

            def run(self, cmd, runner=None):
                if "-writable" in cmd:
                    return "/etc/dahdi/init.conf\n"
                if "init.d" in cmd:
                    return "[ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf\n"
                return ""

        findings, _creds, _blob = run_enum(_S())
        assert any("/etc/dahdi/init.conf" in f.title for f in findings)
