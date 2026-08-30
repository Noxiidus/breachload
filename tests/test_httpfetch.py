"""Resilient curl fetch-policy argv builder."""

from breachload.core.httpfetch import fetch_argv


class TestFetchArgv:
    def test_defaults_follow_and_retry(self):
        argv = fetch_argv("http://x/")
        assert argv[0] == "curl" and "-L" in argv
        assert "--retry" in argv and "--retry-connrefused" in argv
        assert "--max-time" in argv and argv[-1] == "http://x/"

    def test_byte_cap_becomes_range(self):
        argv = fetch_argv("http://x/", max_bytes=131072)
        i = argv.index("-r")
        assert argv[i + 1] == "0-131072"

    def test_no_range_without_cap(self):
        assert "-r" not in fetch_argv("http://x/", max_bytes=None)

    def test_headers_and_no_follow(self):
        argv = fetch_argv("http://x/", follow=False, include_headers=True)
        assert "-L" not in argv and "-i" in argv

    def test_retries_can_be_disabled(self):
        assert "--retry" not in fetch_argv("http://x/", retries=0)

    def test_no_shell_metachars(self):
        # every token must be argv-safe (the validator blocks these in real runs)
        argv = fetch_argv("http://x/", max_bytes=4096, include_headers=True)
        for tok in argv:
            assert not any(c in tok for c in ";|&$`<>\n")
