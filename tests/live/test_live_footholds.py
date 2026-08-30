"""Live integration tests for the auto-foothold modules.

These exercise the real exploit chain against real vulnerable containers (see
`docker-compose.yml`), so we know the foothold modules actually land in the wild —
the one thing the mocked unit tests cannot prove. They are OPT-IN: skipped unless
`BREACHLOAD_LIVE=1` is set AND the target container answers, so a normal `pytest`
run (and CI) never depends on Docker or the network.

Run:
    docker compose -f tests/live/docker-compose.yml up -d
    # wait for the containers to become healthy (Metabase takes ~40s)
    BREACHLOAD_LIVE=1 pytest tests/live -m live -v
    docker compose -f tests/live/docker-compose.yml down
"""

from __future__ import annotations

import os
import socket

import pytest

from breachload.core.session import WebshellSession
from breachload.exploit.footholds import GlpiHtmlawedFoothold, MetabaseFoothold

pytestmark = pytest.mark.live

_LIVE = os.environ.get("BREACHLOAD_LIVE") == "1"


def _reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _require(host: str, port: int) -> None:
    if not _LIVE:
        pytest.skip("live tests are opt-in: set BREACHLOAD_LIVE=1")
    if not _reachable(host, port):
        pytest.skip(f"no live target on {host}:{port} "
                    "(bring up tests/live/docker-compose.yml)")


class TestMetabaseLive:
    def test_metabase_foothold_lands(self):
        _require("127.0.0.1", 3000)
        sess = MetabaseFoothold().establish("127.0.0.1", 3000, scheme="http")
        assert sess is not None, "Metabase CVE-2023-38646 foothold did not land"
        assert isinstance(sess, WebshellSession)
        out = sess.run("id")
        assert "uid=" in out


class TestGlpiLive:
    def test_glpi_foothold_lands(self):
        _require("127.0.0.1", 8081)
        sess = GlpiHtmlawedFoothold().establish("127.0.0.1", 8081, scheme="http")
        assert sess is not None, "GLPI CVE-2022-35914 foothold did not land"
        out = sess.run("id")
        assert "uid=" in out
