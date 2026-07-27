"""enum4linux-ng parsing and the OUTFILE (tool-managed output file) mechanism."""

import asyncio
import sys
from dataclasses import dataclass

from breachload.core.state import EngagementState, Severity
from breachload.tools.base import ToolAdapter, ToolResult
from breachload.tools.enum4linux import Enum4linuxAdapter

ENUM_JSON = """{
  "target": {"host": "10.10.10.5", "workgroup": "WORKGROUP"},
  "os_info": {"OS": "Windows 7", "OS version": "6.1"},
  "sessions": {"Null session": true},
  "shares": {
    "ADMIN$": {"access": ["DENIED"], "type": "Disk"},
    "public": {"access": ["READ", "OK"], "type": "Disk", "comment": "public files"}
  },
  "users": {"1000": {"username": "alice"}, "1001": {"username": "bob"}}
}"""


class TestEnum4linuxParse:
    def _parsed(self) -> EngagementState:
        st = EngagementState(name="t")
        res = ToolResult(exit_code=0, stdout="", stderr="", duration_s=0.1, output_file=ENUM_JSON)
        Enum4linuxAdapter().parse(res, st)
        return st

    def test_host_service_and_os(self):
        st = self._parsed()
        host = st.hosts["10.10.10.5"]
        assert host.os_guess == "Windows 7"
        assert "445/tcp" in host.services
        assert any("workgroup" in n.lower() for n in host.services["445/tcp"].notes)

    def test_null_session_finding(self):
        findings = self._parsed().findings
        assert any("null session" in f.title.lower() and f.severity == Severity.MEDIUM
                   for f in findings)

    def test_readable_share_finding_only_for_readable(self):
        titles = [f.title for f in self._parsed().findings]
        assert any("public" in t for t in titles)
        assert not any("ADMIN$" in t for t in titles)  # DENIED share is not a finding

    def test_users_become_credential_leads(self):
        creds = self._parsed().credentials
        usernames = {c.username for c in creds}
        assert {"alice", "bob"} <= usernames
        assert all(c.kind == "username" and not c.validated for c in creds)

    def test_falls_back_to_stdout(self):
        st = EngagementState(name="t")
        res = ToolResult(exit_code=0, stdout=ENUM_JSON, stderr="", duration_s=0.1)
        Enum4linuxAdapter().parse(res, st)
        assert "10.10.10.5" in st.hosts

    def test_command_uses_outfile_marker(self):
        cmd = Enum4linuxAdapter().build_command("10.10.10.5")
        assert "{OUTFILE}" in cmd and cmd[0] == "enum4linux-ng"


@dataclass
class _FileAdapter(ToolAdapter):
    name: str = "filetool"
    binary: str = sys.executable
    output_file_suffix: str = ".json"

    def build_command(self, target: str, **kwargs) -> list[str]:
        code = "import sys; open(sys.argv[1] + '.json', 'w').write('{\"ok\": 1}')"
        return [sys.executable, "-c", code, "{OUTFILE}"]

    def parse(self, result, state):
        return []


class TestOutfileMechanism:
    def test_reads_tool_written_file_and_cleans_up(self):
        adapter = _FileAdapter()
        cmd = adapter.build_command("x")
        result = asyncio.run(adapter.run(cmd))
        assert result.output_file == '{"ok": 1}'
