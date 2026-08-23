"""Path-MTU / large-response stall probe + the hosts CLI command."""

from typer.testing import CliRunner

import breachload.cli as climod
from breachload.core.netprobe import probe_path_mtu
from breachload.core.state import EngagementState, Host, Service

runner = CliRunner()


class TestMtuProbe:
    def test_detects_mtu_stall(self):
        # Small ranged GET returns 206 fast; full GET times out (curl code 000).
        calls = []

        def fake(argv):
            calls.append(argv)
            ranged = "-r" in argv
            return "206 0.08" if ranged else "000 8.00"

        res = probe_path_mtu("10.10.14.5", runner=fake)
        assert res.ran and res.small_ok and not res.large_ok
        assert "MTU" in res.verdict and "mtu 1300" in res.suggestion

    def test_healthy_path(self):
        res = probe_path_mtu("10.10.14.5", runner=lambda a: "200 0.10")
        assert res.small_ok and res.large_ok and not res.suggestion

    def test_host_down(self):
        res = probe_path_mtu("10.10.14.5", runner=lambda a: "000 8.00")
        assert not res.small_ok and not res.large_ok and "host down" in res.verdict


class TestHostsCommand:
    def _seed(self, tmp_path):
        st = EngagementState(name="t")
        st.hosts["10.10.10.5"] = Host(address="10.10.10.5",
                                      services={"80/tcp": Service(port=80, name="http")})
        st.hosts["app.box.htb"] = Host(address="app.box.htb")
        (tmp_path / "t").mkdir()
        st.save(tmp_path / "t" / "state.json")

    def test_lists_vhost_entries(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        self._seed(tmp_path)
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        result = runner.invoke(climod.app, ["hosts", str(cfg)])
        assert result.exit_code == 0, result.output
        # rich renders the tab as spaces; assert both fields land on one line.
        assert "app.box.htb" in result.output
        assert any("10.10.10.5" in ln and "app.box.htb" in ln
                   for ln in result.output.splitlines())

    def test_no_vhosts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(climod, "ENGAGEMENTS", tmp_path)
        st = EngagementState(name="t")
        st.hosts["10.10.10.5"] = Host(address="10.10.10.5")
        (tmp_path / "t").mkdir()
        st.save(tmp_path / "t" / "state.json")
        cfg = tmp_path / "t.yaml"
        cfg.write_text("name: t\ntargets: ['10.10.10.5']\n", encoding="utf-8")
        result = runner.invoke(climod.app, ["hosts", str(cfg)])
        assert result.exit_code == 0
        assert "no virtual hosts" in result.output
