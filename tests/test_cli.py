"""CLI wiring — the `auto` autopilot flow and state seeding."""


from typer.testing import CliRunner

import breachload.cli as climod
from breachload.cli import _load_or_seed_state, app
from breachload.core.config import EngagementConfig

runner = CliRunner()


class TestSeedState:
    def test_seeds_bare_hosts_only(self, tmp_path):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5", "10.10.10.0/24", "*.acme"])
        state = _load_or_seed_state(cfg, tmp_path / "missing.json")
        assert list(state.hosts) == ["10.10.10.5"]   # CIDR/glob are scope, not hosts

    def test_resumes_existing_state(self, tmp_path):
        cfg = EngagementConfig(name="t", targets=["10.10.10.5"])
        p = tmp_path / "state.json"
        seeded = _load_or_seed_state(cfg, p)
        seeded.upsert_host("10.10.10.9")
        seeded.save(p)
        resumed = _load_or_seed_state(cfg, p)
        assert set(resumed.hosts) == {"10.10.10.5", "10.10.10.9"}


class TestAutoCommand:
    def test_auto_runs_plan_and_writes_report(self, tmp_path, monkeypatch):
        # Point engagements at a temp dir and stub the orchestrator so no real
        # tools are invoked — we're testing the CLI wiring, not the scanners.
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)

        async def _noop(self, *args, **kwargs):
            self.state.upsert_host("10.10.10.5")
            return None

        monkeypatch.setattr(climod.Orchestrator, "run_engagement", _noop)

        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        result = runner.invoke(app, ["auto", str(cfg), "--no-pdf"])

        assert result.exit_code == 0, result.output
        assert "attack plan" in result.output
        assert (tmp_path / "t" / "report.md").exists()

    def test_auto_writes_pdf_when_requested(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)

        async def _noop(self, *args, **kwargs):
            return None

        monkeypatch.setattr(climod.Orchestrator, "run_engagement", _noop)
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        result = runner.invoke(app, ["auto", str(cfg), "--pdf"])
        assert result.exit_code == 0, result.output
        pdf = tmp_path / "t" / "report.pdf"
        assert pdf.exists() and pdf.read_bytes().startswith(b"%PDF-1.4")


class TestUtilityCommands:
    def test_doctor_runs(self):
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "environment" in result.output and "nmap" in result.output

    def test_gtfo_known_binary(self):
        result = runner.invoke(app, ["gtfo", "find"])
        assert result.exit_code == 0
        assert "suid" in result.output

    def test_gtfo_unknown_binary(self):
        result = runner.invoke(app, ["gtfo", "no-such-bin"])
        assert result.exit_code == 1

    def test_flag_records_from_text(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        from breachload.core.state import EngagementState
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        result = runner.invoke(app, ["flag", str(cfg), "--text", "root: flag{pwned_it}"])
        assert result.exit_code == 0 and "flag{pwned_it}" in result.output
        state = EngagementState.load(tmp_path / "t" / "state.json")
        assert "flag{pwned_it}" in state.flags

    def test_loot_parses_findings_and_creds(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        from breachload.core.state import EngagementState
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        loot_text = "(root) NOPASSWD: /usr/bin/find\npassword=Sup3rSecret"
        result = runner.invoke(app, ["loot", str(cfg), "--text", loot_text])
        assert result.exit_code == 0
        state = EngagementState.load(tmp_path / "t" / "state.json")
        assert any("find" in f.title for f in state.findings)
        assert any(c.secret == "Sup3rSecret" for c in state.credentials)
