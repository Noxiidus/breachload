"""doctor --self-test — every adapter passes the Validator without touching a target."""

from typer.testing import CliRunner

from breachload.cli import app


class TestDoctorSelfTest:
    def test_passes_on_the_current_registry(self):
        r = CliRunner().invoke(app, ["doctor", "--self-test"])
        assert r.exit_code == 0
        assert "all adapters pass" in r.output
        # Every adapter should be listed as passing.
        assert "REFUSED" not in r.output and "CRASHED" not in r.output

    def test_reports_a_broken_adapter(self, monkeypatch):
        # Inject a broken adapter into the registry and confirm the self-test
        # exits non-zero with a REFUSED/CRASHED line for it.
        from breachload.safety.validator import Risk
        from breachload.tools import registry as reg_mod
        from breachload.tools.base import ToolAdapter

        class _BadAdapter(ToolAdapter):
            def build_command(self, target, **_):
                return ["curl", target, "; rm -rf /"]   # blocked by validator

            def parse(self, result, state):  # pragma: no cover
                return []

        orig = reg_mod.default_registry

        def patched(load_plugins=True):
            reg = orig(load_plugins=False)
            bad = _BadAdapter(name="shellshock", binary="curl", risk=Risk.RECON)
            reg[bad.name] = bad
            return reg

        monkeypatch.setattr(reg_mod, "default_registry", patched)
        # cli.py imports default_registry inside doctor(), so the patch takes.
        import breachload.tools.registry as rmod  # noqa: F401
        r = CliRunner().invoke(app, ["doctor", "--self-test"])
        assert r.exit_code == 1
        assert "shellshock" in r.output
