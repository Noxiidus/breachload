"""Generalized Windows privesc-class detectors."""

import pytest

from breachload.analysis.winprivesc_classes import (
    find_all_windows,
    find_gpp_cpassword,
    find_weak_service_acl,
    find_writable_scheduled_tasks,
)

try:
    import cryptography  # noqa: F401
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False
requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO,
                                     reason="cryptography not installed")


# A real GPP cpassword blob for user "vagrant" with password "vagrant". Sourced
# from the well-known Microsoft GPP AES sample used across every references list.
_GPP_XML = (
    '<Groups>'
    '<User name="admin" newName="" fullName="" description="">'
    '<Properties action="U" newName="" fullName="" description="" '
    'cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" '
    'changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" '
    'userName="admin"/>'
    '</User>'
    '</Groups>')

_SCHTASKS = (
    "Folder: \\\n"
    "HostName: WIN-BOX\n"
    "Task Name: \\VulnTask\n"
    "Task To Run: C:\\ProgramData\\vuln\\run.exe /once\n"
    "Run As User: NT AUTHORITY\\SYSTEM\n"
    "Schedule: Daily\n"
)

_ACCESSCHK = (
    "vulnsvc\n"
    "  RW NT AUTHORITY\\Authenticated Users\n"
    "        SERVICE_CHANGE_CONFIG\n"
)


class TestGppCpassword:
    def test_finding_captured_even_without_crypto(self):
        f, _c = find_gpp_cpassword(_GPP_XML, host="dc01")
        assert f and "GPP cpassword recovered" in f[0].title
        # Regardless of the crypto backend, we always flag the finding.
        assert f[0].severity.value == "critical"

    def test_username_pulled_from_context(self):
        f, _c = find_gpp_cpassword(_GPP_XML)
        assert "admin" in f[0].title

    @requires_crypto
    def test_decrypts_to_known_password(self):
        # The famous cpassword blob decrypts to "Local*P4ssword!" (Microsoft's
        # documented sample); with the public key + our helper we recover it.
        _f, creds = find_gpp_cpassword(_GPP_XML)
        assert creds
        # The known plaintext for that specific blob is "Local*P4ssword!".
        assert creds[0].secret == "Local*P4ssword!"

    def test_no_cpassword_no_finding(self):
        assert find_gpp_cpassword("<Groups></Groups>") == ([], [])


class TestScheduledTasks:
    def test_writable_action_flagged(self):
        writable = {"C:\\ProgramData\\vuln\\run.exe"}
        f = find_writable_scheduled_tasks(_SCHTASKS, writable, host="win")
        assert f and "run.exe" in f[0].title
        assert "SYSTEM" in f[0].evidence

    def test_not_writable_no_finding(self):
        f = find_writable_scheduled_tasks(_SCHTASKS, set())
        assert f == []


class TestWeakServiceAcl:
    def test_change_config_flagged(self):
        f = find_weak_service_acl(_ACCESSCHK, host="win")
        assert f and "vulnsvc" in f[0].title
        assert "sc config" in f[0].exploit

    def test_no_acl_no_finding(self):
        assert find_weak_service_acl("nothing interesting here") == []


class TestFindAllWindows:
    def test_runs_every_class(self):
        combined = _GPP_XML + "\n" + _SCHTASKS + "\n" + _ACCESSCHK
        writable = {"C:\\ProgramData\\vuln\\run.exe"}
        f, _c = find_all_windows(combined)
        # scheduled task detector needs the writable set passed in for now, so
        # we exercise both entry points.
        assert any("GPP cpassword" in x.title for x in f)
        assert any("Writable service ACL" in x.title for x in f)
        # scheduled task needs the writable path list
        f_task = find_writable_scheduled_tasks(_SCHTASKS, writable)
        assert f_task and "run.exe" in f_task[0].title
