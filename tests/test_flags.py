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

    def test_bare_hex_ignored_by_default(self):
        # A bare 32-hex token collides with MD5 hashes, so it is off by default.
        assert find_flags("a1b2c3d4e5f60718293a4b5c6d7e8f90") == []

    def test_bare_hex_captured_when_opted_in(self):
        htb = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        assert find_flags(htb, include_bare_hex=True) == [htb]

    def test_bare_hex_needs_full_32(self):
        # 31 or 33 chars, or non-hex, must not match even when opted in.
        assert find_flags("a1b2c3d4e5f60718293a4b5c6d7e8f9", include_bare_hex=True) == []
        assert find_flags("z1b2c3d4e5f60718293a4b5c6d7e8f90", include_bare_hex=True) == []

    def test_bare_hex_and_braced_together(self):
        htb = "0123456789abcdef0123456789abcdef"
        out = find_flags(f"flag{{one}} {htb}", include_bare_hex=True)
        assert out == ["flag{one}", htb]
