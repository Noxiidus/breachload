"""Beginner-mode features: explain glossary, init wizard, dry-run, doctor --install,
attack-path narrative."""

from typer.testing import CliRunner

import breachload.cli as climod
from breachload.analysis.glossary import all_terms, lookup
from breachload.core.config import EngagementConfig
from breachload.core.state import Credential, EngagementState, Finding, Service, Severity
from breachload.report.engine import render_markdown

runner = CliRunner()


class TestGlossary:
    def test_lookup_by_key_and_alias(self):
        assert lookup("ssti").key == "ssti"
        assert lookup("template injection").key == "ssti"
        assert lookup("KERBEROASTING").key == "kerberoast"

    def test_unknown_term(self):
        assert lookup("banana") is None

    def test_all_terms_have_fields(self):
        for t in all_terms():
            assert t.what and t.why and t.breachload

    def test_explain_command(self):
        result = runner.invoke(climod.app, ["explain", "esc1"])
        assert result.exit_code == 0
        assert "ESC1" in result.output and "Why it matters" in result.output

    def test_explain_lists_terms(self):
        result = runner.invoke(climod.app, ["explain"])
        assert result.exit_code == 0 and "kerberoast" in result.output


class TestInit:
    def test_writes_yaml_non_interactive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        out = tmp_path / "box.yaml"
        result = runner.invoke(climod.app, [
            "init", "--name", "box", "--targets", "10.10.10.5,box.htb",
            "--lhost", "10.10.14.7", "--output", str(out)])
        assert result.exit_code == 0, result.output
        cfg = EngagementConfig.load(out)
        assert cfg.name == "box" and "10.10.10.5" in cfg.targets and cfg.lhost == "10.10.14.7"


class TestDryRun:
    def test_dry_run_does_not_execute(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        # No adapter should actually run; if one did it would try real tools.
        result = runner.invoke(climod.app, ["run", str(cfg), "--dry-run"])
        assert result.exit_code == 0, result.output
        assert "DRY-RUN" in result.output


class TestDoctorInstall:
    def test_install_prints_hints_for_missing(self, monkeypatch):
        # Force everything to look missing so the install section always renders.
        from breachload.core import environment
        monkeypatch.setattr(environment, "check_tools",
                            lambda: [environment.ToolStatus("nmap", "recon", None)])
        monkeypatch.setattr(climod, "check_tools", environment.check_tools)
        result = runner.invoke(climod.app, ["doctor", "--install"])
        assert result.exit_code == 0
        assert "apt install" in result.output and "nmap" in result.output


class TestAttackPathNarrative:
    def test_narrative_tells_the_story(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.9")
        h.upsert_service(Service(port=80, name="http"))
        st.add_finding(Finding(title="Grafana LFI", host="10.10.10.9", severity=Severity.HIGH,
                               cve=["CVE-2021-43798"], exploit="curl ..."))
        st.add_finding(Finding(title="Passwordless sudo: tar", host="10.10.10.9",
                               severity=Severity.HIGH))
        st.credentials.append(Credential(username="bob", secret="pw"))
        st.add_flag("flag{done}")
        md = render_markdown(st)
        assert "## Attack path" in md
        assert "Recon mapped" in md
        assert "foothold leads" in md.lower()
        assert "credential" in md.lower() and "Privilege-escalation leads" in md
        assert "Captured 1 flag" in md
