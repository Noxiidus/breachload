"""Generalized deserialization payload generation by stack."""

from breachload.analysis.deserialization import (
    payload_commands,
    payload_commands_for_state,
    stacks_for,
)
from breachload.core.state import EngagementState, Service


class TestStackMatching:
    def test_tomcat_is_java(self):
        stacks = stacks_for("Apache Tomcat 9")
        assert stacks and stacks[0][0] == "java"

    def test_laravel_is_php(self):
        stacks = stacks_for("Laravel 10")
        assert stacks and stacks[0][0] == "php"

    def test_aspnet_is_dotnet(self):
        stacks = stacks_for("Microsoft-IIS/10 ASPNET")
        assert stacks and stacks[0][0] == "dotnet"

    def test_no_stack_no_match(self):
        assert stacks_for("nothing") == []

    def test_language_deduped(self):
        # Multiple Java tokens -> only one Java entry.
        stacks = stacks_for("tomcat jenkins spring hibernate")
        langs = [s[0] for s in stacks]
        assert langs.count("java") == 1


class TestPayloadCommands:
    def test_java_uses_ysoserial(self):
        rows = payload_commands("id", "tomcat")
        assert rows and rows[0][2][0] == "ysoserial"
        # Every argv ends with the command
        assert all(argv[-1] == "id" for _l, _g, argv in rows)

    def test_php_uses_phpggc(self):
        rows = payload_commands("id", "laravel")
        assert rows and rows[0][2][0] == "phpggc"

    def test_dotnet_uses_ysoserial_net_with_formatter(self):
        rows = payload_commands("whoami", "aspnet")
        assert rows and rows[0][2][0] == "ysoserial.net"
        joined = " ".join(rows[0][2])
        assert "-g" in joined and "-c" in joined and "-f" in joined


class TestStateDriven:
    def test_derives_from_service_notes(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.5")
        h.upsert_service(Service(port=8080, name="http", notes=["webapp: Apache Tomcat 9"]))
        rows = payload_commands_for_state("id", st)
        assert rows and rows[0][0] == "10.10.10.5"
        assert any(lang == "java" for _h, lang, _g, _a in rows)

    def test_multi_service_multi_stack(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.6")
        h.upsert_service(Service(port=8080, name="http", notes=["Apache Tomcat"]))
        h.upsert_service(Service(port=80, name="http", notes=["Laravel"]))
        rows = payload_commands_for_state("id", st)
        langs = {lang for _h, lang, _g, _a in rows}
        assert "java" in langs and "php" in langs

    def test_no_service_no_output(self):
        st = EngagementState(name="t")
        assert payload_commands_for_state("id", st) == []
