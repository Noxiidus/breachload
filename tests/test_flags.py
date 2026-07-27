"""CTF flag detection."""

from breachload.analysis.flags import find_flags


class TestFindFlags:
    def test_flag_brace(self):
        assert find_flags("here flag{abc_123} done") == ["flag{abc_123}"]

    def test_prefixed_formats(self):
        assert "HTB{y0u_got_it}" in find_flags("output HTB{y0u_got_it}")
        assert "root{secret}" in find_flags("root{secret}")

    def test_unique_and_ordered(self):
        assert find_flags("flag{a} x flag{b} flag{a}") == ["flag{a}", "flag{b}"]

    def test_no_flags(self):
        assert find_flags("nothing to see") == []

    def test_empty(self):
        assert find_flags("") == []

    def test_does_not_span_newline(self):
        assert find_flags("flag{unclosed\nnext line}") == []
