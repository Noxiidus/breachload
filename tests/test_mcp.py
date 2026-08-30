"""MCP server — JSON-RPC handlers over breachload's safe surface."""

import json

from breachload.mcp.server import TOOLS, handle


def _call(name, args):
    resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
    return resp["result"]["content"][0]["text"]


class TestProtocol:
    def test_initialize(self):
        r = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert r["result"]["serverInfo"]["name"] == "breachload"
        assert "protocolVersion" in r["result"]

    def test_initialized_notification_is_silent(self):
        assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def test_tools_list(self):
        r = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in r["result"]["tools"]}
        assert "fingerprint_to_cve" in names and "ad_killchain" in names
        # every tool advertises a schema
        for t in r["result"]["tools"]:
            assert t["inputSchema"]["type"] == "object"

    def test_unknown_method(self):
        r = handle({"jsonrpc": "2.0", "id": 3, "method": "does/notexist"})
        assert r["error"]["code"] == -32601

    def test_unknown_tool(self):
        r = handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "nope", "arguments": {}}})
        assert r["error"]["code"] == -32602


class TestTools:
    def test_fingerprint_to_cve(self):
        out = _call("fingerprint_to_cve", {"fingerprint": "webapp: Apache NiFi"})
        assert "NiFi" in out and "CVE-2023-34468" in out

    def test_ad_killchain(self):
        out = _call("ad_killchain", {"finding_titles": [
            "Kerberoastable account: svc", "ACL: GetChanges over corp.local"]})
        assert "DCSYNC" in out and "KERBEROAST" in out

    def test_parse_roast(self):
        out = _call("parse_roast", {
            "output": "$krb5asrep$23$bob@CORP.LOCAL:aaaa$bbbb"})
        assert "bob" in out

    def test_identify_hash(self):
        out = _call("identify_hash", {"hash": "$2b$12$" + "a" * 53})
        assert "hashcat" in out.lower()

    def test_pivot_plan(self):
        out = _call("pivot_plan", {"via": "10.0.0.5", "subnet": "172.16.5.0/24",
                                   "lhost": "10.10.14.2"})
        assert "chisel" in out or "sshuttle" in out

    def test_gtfobins(self):
        out = _call("gtfobins", {"binary": "find"})
        assert out  # returns something (entry json or 'no entry')

    def test_parse_nmap_xml_reads_real_xml(self):
        xml = ('<?xml version="1.0"?><nmaprun><host>'
               '<address addr="10.10.10.5" addrtype="ipv4"/>'
               '<ports><port portid="22" protocol="tcp"><state state="open"/>'
               '<service name="ssh" product="OpenSSH"/></port></ports>'
               '</host></nmaprun>')
        out = _call("parse_nmap_xml", {"xml": xml})
        assert "10.10.10.5" in out and "ssh" in out

    def test_fingerprint_no_lead_message(self):
        out = _call("fingerprint_to_cve", {"fingerprint": "totally unknown app 9.9"})
        assert "no known-CVE leads" in out

    def test_tool_error_is_reported_not_raised(self):
        # Missing required arg -> handled as isError content, not a crash.
        resp = handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                       "params": {"name": "identify_hash", "arguments": {}}})
        assert "result" in resp  # no JSON-RPC error; tool-level error inside

    def test_every_tool_is_callable(self):
        # Smoke: each tool with an empty-ish arg set returns content (or reports an
        # error as content), never raising.
        for name in TOOLS:
            resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": {}}})
            assert "result" in resp
            assert json.dumps(resp)  # serialisable
