"""Generalized Linux privesc-class detectors."""

from breachload.analysis.privesc_classes import (
    find_all,
    find_path_hijacks,
    find_writable_service_units,
    find_writable_suid_binaries,
)

_ENUM_PATH_HIJACK = """$ env
PATH=/tmp/user_bin:/usr/local/bin:/usr/bin:/bin
HOME=/home/bob
$ find / -writable -type d 2>/dev/null | head
/tmp/user_bin
/home/bob
$ cat /etc/cron.d/* /etc/crontab
*/5 * * * * root backup.sh
"""

_ENUM_ABS_PATH = """$ env
PATH=/tmp/user_bin:/usr/bin
$ find / -writable -type d 2>/dev/null
/tmp/user_bin
$ cat /etc/crontab
*/5 * * * * root /usr/bin/backup.sh
"""

_ENUM_UNIT = """$ find / -writable -type f 2>/dev/null | head
/etc/systemd/system/vulnservice.service
/tmp/junk
"""

_ENUM_SUID = """$ find / -writable -type f 2>/dev/null | head
/opt/tools/vulnsuid
$ find / -perm -4000 -type f 2>/dev/null | head
/usr/bin/passwd
/opt/tools/vulnsuid
"""


class TestPathHijack:
    def test_detects_bareword_with_writable_in_path(self):
        f = find_path_hijacks(_ENUM_PATH_HIJACK)
        assert f and "backup.sh" in f[0].title
        assert "/tmp/user_bin" in f[0].evidence
        assert f[0].severity.value == "high"

    def test_absolute_path_not_hijackable(self):
        # root runs /usr/bin/backup.sh -> not a bareword -> no PATH hijack
        assert find_path_hijacks(_ENUM_ABS_PATH) == []

    def test_no_writable_in_path_no_finding(self):
        enum = ("$ env\nPATH=/usr/bin:/bin\n"
                "$ find / -writable -type d\n/home/bob\n"
                "$ cat /etc/crontab\n*/5 * * * * root backup.sh\n")
        assert find_path_hijacks(enum) == []

    def test_dedup(self):
        enum = _ENUM_PATH_HIJACK + "\n$ cat /etc/crontab\n*/5 * * * * root backup.sh\n"
        assert len(find_path_hijacks(enum)) == 1


class TestWritableUnit:
    def test_detects_writable_service_file(self):
        f = find_writable_service_units(_ENUM_UNIT)
        assert f and "vulnservice.service" in f[0].title
        assert f[0].severity.value == "high"
        assert "daemon-reload" in f[0].exploit

    def test_ignores_writable_non_service(self):
        enum = ("$ find / -writable -type f 2>/dev/null\n/tmp/nonservice.txt\n")
        assert find_writable_service_units(enum) == []


class TestWritableSuid:
    def test_writable_suid_is_critical(self):
        f = find_writable_suid_binaries(_ENUM_SUID)
        assert f and f[0].severity.value == "critical"
        assert "/opt/tools/vulnsuid" in f[0].title

    def test_non_writable_suid_ignored(self):
        enum = ("$ find / -writable -type f\n/tmp/x\n"
                "$ find / -perm -4000 -type f\n/usr/bin/passwd\n")
        assert find_writable_suid_binaries(enum) == []


class TestFindAll:
    def test_runs_every_detector(self):
        # One combined enum blob covering all three classes; distinct block
        # headers so `_blocks` doesn't collapse the writable listings.
        combined = ("$ env\nPATH=/tmp/user_bin:/usr/bin\n"
                    "$ find / -writable -type d 2>/dev/null\n/tmp/user_bin\n"
                    "$ find / -writable -type f 2>/dev/null\n"
                    "/etc/systemd/system/vulnservice.service\n/opt/tools/vulnsuid\n"
                    "$ cat /etc/crontab\n*/5 * * * * root backup.sh\n"
                    "$ find / -perm -4000 -type f 2>/dev/null\n/opt/tools/vulnsuid\n")
        titles = [f.title for f in find_all(combined)]
        assert any("PATH hijack" in t for t in titles)
        assert any("Writable systemd unit" in t for t in titles)
        assert any("Writable SUID root binary" in t for t in titles)


class TestWiredIntoEnum:
    def test_run_enum_returns_class_findings(self):
        from breachload.analysis.privesc_auto import run_enum

        class _S:
            host = "1.2.3.4"

            def run(self, cmd, runner=None):
                if "env" in cmd and "grep" in cmd:
                    return ""
                if cmd.strip().startswith("env"):
                    return "PATH=/tmp/user_bin:/usr/bin\n"
                if "-writable -type f" in cmd:
                    return ("/etc/systemd/system/vulnservice.service\n"
                            "/opt/tools/vulnsuid\n/tmp/user_bin\n")
                if "-writable -type d" in cmd:
                    # Some older enums use `-writable -type d`; not used here,
                    # our enum uses `-writable -type f`. Return the dir listing
                    # via the type-f path so the detector sees it as well.
                    return "/tmp/user_bin\n"
                if "perm -4000" in cmd:
                    return "/opt/tools/vulnsuid\n"
                if "cron" in cmd:
                    return "*/5 * * * * root backup.sh\n"
                return ""

        findings, _c, _b = run_enum(_S())
        titles = [f.title for f in findings]
        assert any("Writable SUID root binary" in t for t in titles)
