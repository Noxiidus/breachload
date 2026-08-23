"""Linux privilege-escalation enumeration playbook + its wiring into suggest."""

from breachload.analysis.privesc_enum import enumeration_playbook, playbook_lines
from breachload.analysis.suggest import SuggestionEngine
from breachload.core.state import EngagementState, Service


class TestPlaybook:
    def test_fills_lhost_into_transfer_commands(self):
        lines = "\n".join(playbook_lines("10.10.14.7", http_port=8001))
        assert "http://10.10.14.7:8001/linpeas.sh" in lines
        assert "python3 -m http.server 8001" in lines
        assert "breachload loot" in lines

    def test_steps_are_ordered_and_titled(self):
        steps = enumeration_playbook()
        titles = [s.title for s in steps]
        assert titles[0].startswith("1.") and titles[-1].startswith("6.")
        assert any("linpeas" in c for s in steps for c in s.commands)
        assert any("pspy" in c for s in steps for c in s.commands)

    def test_no_embedded_newlines_in_commands(self):
        for step in enumeration_playbook():
            assert all("\n" not in c for c in step.commands)


class TestSuggestWiring:
    def test_post_shell_uses_playbook_with_lhost(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.5").upsert_service(Service(port=22, name="ssh"))
        suggestions = SuggestionEngine().suggest(st, lhost="10.10.14.7")
        post = next(s for s in suggestions if "privilege-escalation" in s.title)
        joined = "\n".join(post.actions)
        assert "10.10.14.7" in joined and "linpeas" in joined
