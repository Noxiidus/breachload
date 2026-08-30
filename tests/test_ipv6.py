"""IPv6 handling — host bracketing in URLs and scope."""

from breachload.core.llm import _svc_url
from breachload.core.netutil import bracket, host_port, host_url, is_ipv6
from breachload.core.state import Service
from breachload.safety.scope import Scope, extract_targets
from breachload.tools.whatweb import _as_url, _split_target


class TestNetutil:
    def test_is_ipv6(self):
        assert is_ipv6("dead:beef::1")
        assert is_ipv6("::1")
        assert is_ipv6("[::1]")
        assert not is_ipv6("10.10.10.5")
        assert not is_ipv6("example.com")

    def test_bracket(self):
        assert bracket("dead:beef::1") == "[dead:beef::1]"
        assert bracket("[::1]") == "[::1]"       # already bracketed
        assert bracket("10.10.10.5") == "10.10.10.5"
        assert bracket("example.com") == "example.com"

    def test_host_url_ipv6(self):
        assert host_url("::1", 8080, "http") == "http://[::1]:8080"
        assert host_url("10.10.10.5", 443, "https") == "https://10.10.10.5:443"

    def test_host_port_ipv6(self):
        assert host_port("fe80::1", 445) == "[fe80::1]:445"
        assert host_port("10.0.0.1", 445) == "10.0.0.1:445"


class TestUrlBuildersIPv6:
    def test_as_url_brackets_ipv6(self):
        assert _as_url("dead:beef::1") == "http://[dead:beef::1]"
        assert _as_url("http://[::1]:80") == "http://[::1]:80"  # already a URL
        assert _as_url("10.10.10.5") == "http://10.10.10.5"

    def test_svc_url_brackets_ipv6(self):
        assert _svc_url("::1", Service(port=80, name="http")) == "http://[::1]:80"

    def test_split_target_parses_bracketed_ipv6(self):
        host, port, scheme = _split_target("dead:beef::1")
        assert host == "dead:beef::1" and port == 80 and scheme == "http"


class TestScopeIPv6:
    def test_ipv6_network_allows(self):
        sc = Scope.from_config(["dead:beef::/64"])
        assert sc.allows("dead:beef::5")
        assert not sc.allows("dead:be:ffff::5")   # outside the /64

    def test_extract_bracketed_ipv6_from_url(self):
        found = extract_targets(["curl", "http://[dead:beef::1]:8080/x"])
        assert "dead:beef::1" in found

    def test_extract_bare_ipv6(self):
        found = extract_targets(["nmap", "dead:beef::1"])
        assert "dead:beef::1" in found
