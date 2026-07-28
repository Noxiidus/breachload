"""httpx adapter — HTTP fingerprint enrichment."""

import json

from breachload.core.state import EngagementState
from breachload.tools.base import ToolResult
from breachload.tools.httpx import HttpxAdapter

_LINE = json.dumps({
    "host": "10.10.10.5", "port": "80", "scheme": "http",
    "url": "http://10.10.10.5", "status_code": 200, "title": "Welcome home",
    "webserver": "Apache/2.4.49", "tech": ["Apache HTTP Server:2.4.49", "PHP:7.4"],
})


class TestHttpxAdapter:
    def setup_method(self):
        self.a = HttpxAdapter()

    def test_build_command_has_url_and_json(self):
        cmd = self.a.build_command("10.10.10.5")
        assert cmd[0] == "httpx" and "-json" in cmd
        assert "http://10.10.10.5" in cmd

    def test_parse_enriches_service(self):
        state = EngagementState(name="t")
        notes = self.a.parse(ToolResult(0, _LINE, "", 0.1), state)
        svc = state.hosts["10.10.10.5"].services["80/tcp"]
        assert svc.product == "Apache/2.4.49"
        assert any("Welcome home" in n for n in svc.notes)
        assert any("PHP:7.4" in n for n in svc.notes)
        assert notes and "10.10.10.5" in notes[0]

    def test_parse_falls_back_to_url_when_host_missing(self):
        line = json.dumps({"url": "https://10.10.10.9:8443", "title": "Admin"})
        state = EngagementState(name="t")
        self.a.parse(ToolResult(0, line, "", 0.1), state)
        assert "8443/tcp" in state.hosts["10.10.10.9"].services

    def test_parse_no_json(self):
        notes = self.a.parse(ToolResult(1, "not json", "", 0.1), EngagementState(name="t"))
        assert "no parseable JSON" in notes[0]
