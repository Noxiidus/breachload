"""Web attack-surface probes + group-based privesc + suggest wiring."""

from breachload.analysis.postexploit import loot, parse_groups
from breachload.analysis.suggest import SuggestionEngine
from breachload.analysis.webattacks import probe_lines, web_probes
from breachload.core.state import EngagementState, Service, Severity


class TestWebProbes:
    def test_covers_the_core_injection_classes(self):
        techs = [p.technique for p in web_probes("http://t:80")]
        for expected in ("SSTI", "SQL", "LFI", "upload", "Command", "SSRF", "XXE", "JWT"):
            assert any(expected.lower() in t.lower() for t in techs), expected

    def test_renders_url_and_imds(self):
        lines = "\n".join(probe_lines("http://10.10.10.9:80"))
        assert "http://10.10.10.9:80" in lines
        assert "169.254.169.254" in lines           # cloud metadata SSRF
        assert "7*7" in lines                        # SSTI tell

    def test_suggest_emits_one_block_per_http_host(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.9").upsert_service(Service(port=8080, name="http-proxy"))
        out = SuggestionEngine().suggest(st)
        web = [s for s in out if "attack-surface" in s.title]
        assert len(web) == 1 and "10.10.10.9:8080" in web[0].title


class TestGroupPrivesc:
    def test_docker_group_flagged_critical(self):
        text = "uid=1000(bob) gid=1000(bob) groups=1000(bob),999(docker)"
        findings = parse_groups(text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "docker run" in findings[0].exploit

    def test_lxd_and_disk(self):
        assert any("lxd" in f.title for f in parse_groups("groups=lxd"))
        assert any("disk" in f.title for f in parse_groups("groups=disk"))

    def test_no_privesc_group(self):
        assert parse_groups("groups=1000(bob),4(adm-nope),100(users)") == []

    def test_wired_into_loot(self):
        findings, _ = loot("uid=0 groups=docker,sudo\n")
        assert any("docker" in f.title for f in findings)


class TestAuthAwareRecrawl:
    def test_ffuf_cookie_flag(self):
        from breachload.tools.ffuf import FfufAdapter
        cmd = FfufAdapter().build_command("http://t", cookie="sess=abc")
        assert "-H" in cmd and any("Cookie: sess=abc" in tok for tok in cmd)

    def test_recrawl_suggested_when_creds_exist(self):
        from breachload.core.state import Credential
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.9").upsert_service(Service(port=80, name="http"))
        st.credentials.append(Credential(username="bob", secret="pw"))
        out = SuggestionEngine().suggest(st)
        web = next(s for s in out if "attack-surface" in s.title)
        assert any("authenticated re-crawl" in a for a in web.actions)

    def test_no_recrawl_without_creds(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.9").upsert_service(Service(port=80, name="http"))
        web = next(s for s in SuggestionEngine().suggest(st) if "attack-surface" in s.title)
        assert not any("authenticated re-crawl" in a for a in web.actions)
