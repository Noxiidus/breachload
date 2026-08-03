"""Artifact delivery — the scope- and confirmation-gated exploitation step."""

import asyncio

from breachload.core.state import Artifact
from breachload.exploit.delivery import (
    ScriptDelivery,
    UploadDelivery,
    deliver_artifact,
    method_by_name,
)
from breachload.exploit.runner import RunResult
from breachload.safety.scope import Scope
from breachload.safety.validator import Risk, Validator

ARTIFACT = Artifact(name="poc.py", kind="poc", path="/tmp/poc.py", platform="linux")


def _validator(binary: str, threshold: Risk | None = Risk.ACTIVE) -> Validator:
    # Default ACTIVE threshold => EXPLOIT-risk delivery requires confirmation.
    scope = Scope.from_config(["10.10.10.0/24"])
    return Validator(scope, {binary}, threshold)


async def _ok_runner(command):
    return RunResult(0, "pwned", "")


async def _fail_runner(command):
    return RunResult(1, "", "connection refused")


class TestBuildCommand:
    def test_script_method(self):
        cmd = ScriptDelivery(interpreter="python3").build_command(ARTIFACT, "10.10.10.5")
        assert cmd == ["python3", "/tmp/poc.py", "10.10.10.5"]

    def test_upload_method(self):
        cmd = UploadDelivery().build_command(ARTIFACT, "10.10.10.5")
        assert cmd[0] == "curl" and "file=@/tmp/poc.py" in cmd
        assert "http://10.10.10.5" in cmd

    def test_method_by_name(self):
        assert method_by_name("upload").name == "upload"
        assert method_by_name("anything-else").name == "script"


class TestGating:
    def test_out_of_scope_is_blocked(self):
        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "8.8.8.8", v,
                                         confirm=lambda _: True, runner=_ok_runner))
        assert r.status == "blocked" and "out-of-scope" in r.reason

    def test_needs_confirmation_and_declined(self):
        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                         confirm=lambda _: False, runner=_ok_runner))
        assert r.status == "declined"

    def test_no_confirm_callback_declines(self):
        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                         confirm=None, runner=_ok_runner))
        assert r.status == "declined"

    def test_confirmed_and_delivered(self):
        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                         confirm=lambda _: True, runner=_ok_runner))
        assert r.status == "delivered" and r.ok

    def test_failed_delivery(self):
        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                         confirm=lambda _: True, runner=_fail_runner))
        assert r.status == "failed" and not r.ok

    def test_full_auto_exploit_threshold_no_confirm_needed(self):
        # If the engagement auto-threshold covers EXPLOIT, delivery runs without asking.
        v = _validator("python3", threshold=Risk.EXPLOIT)
        # EXPLOIT is not > EXPLOIT, so no confirmation required.
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                         confirm=None, runner=_ok_runner))
        assert r.status == "delivered"

    def test_missing_artifact_path(self):
        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), Artifact(name="x"), "10.10.10.5", v,
                                         confirm=lambda _: True, runner=_ok_runner))
        assert r.status == "failed" and "no path" in r.reason

    def test_async_confirm_is_awaited(self):
        # An async confirm (e.g. the web UI gate) must be awaited, not treated as
        # a truthy coroutine that runs delivery unconditionally.
        async def approve(_prompt):
            return True

        async def deny(_prompt):
            return False

        v = _validator("python3")
        r = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                         confirm=approve, runner=_ok_runner))
        assert r.status == "delivered"
        r2 = asyncio.run(deliver_artifact(ScriptDelivery(), ARTIFACT, "10.10.10.5", v,
                                          confirm=deny, runner=_ok_runner))
        assert r2.status == "declined"
