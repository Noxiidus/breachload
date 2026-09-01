"""Generalized auth-aware crawl: login argv + session extraction."""

from breachload.analysis.auth_crawl import (
    basic_auth_argv,
    extract_session,
    login_argv,
    looks_like_success,
    try_login_ladder,
)


class TestArgv:
    def test_login_argv_posts_form(self):
        argv = login_argv("http://x/login", "alice", "s3cr3t")
        joined = " ".join(argv)
        assert "-X POST" in joined and "username=alice&password=s3cr3t" in joined
        assert "-c" in argv                       # cookie jar written

    def test_login_argv_custom_fields(self):
        argv = login_argv("http://x/", "u", "p", user_field="log", pw_field="pwd")
        assert "log=u&pwd=p" in " ".join(argv)

    def test_basic_auth_uses_dash_u(self):
        argv = basic_auth_argv("http://x/", "admin", "admin")
        assert "-u" in argv and "admin:admin" in argv


class TestLadder:
    def test_covers_common_paths(self):
        rungs = try_login_ladder("http://x", "u", "p")
        labels = " ".join(r[0] for r in rungs)
        for p in ("/login", "/wp-login.php", "/admin/login", "/api/login"):
            assert p in labels
        # Basic-auth rung at the end
        assert any("Basic auth" in r[0] for r in rungs)

    def test_ladder_argv_is_curl_only(self):
        for _label, argv in try_login_ladder("http://x", "u", "p"):
            assert argv[0] == "curl"


class TestExtractSession:
    def test_extracts_session_cookie(self):
        r = ("HTTP/1.1 302 Found\r\n"
             "Set-Cookie: PHPSESSID=abc123def; Path=/\r\n"
             "Set-Cookie: tracking=xyz; Path=/\r\n"
             "Location: /dashboard\r\n\r\n")
        s = extract_session(r)
        # session cookie is preferred over the tracking one
        assert s["cookie"].startswith("PHPSESSID=")
        assert s["location"] == "/dashboard"
        assert "all_cookies" in s

    def test_extracts_bearer_token(self):
        r = 'HTTP/1.1 200 OK\r\n\r\n{"access_token":"eyJabc.def.ghi","type":"Bearer"}'
        s = extract_session(r)
        assert s["bearer"] == "eyJabc.def.ghi"

    def test_empty(self):
        assert extract_session("") == {}
        assert extract_session(None) == {}


class TestLooksLikeSuccess:
    def test_bearer_is_success(self):
        assert looks_like_success('{"access_token":"tok"}')

    def test_session_cookie_plus_dashboard_redirect(self):
        r = ("HTTP/1.1 302 Found\r\n"
             "Set-Cookie: SESSION=abc\r\n"
             "Location: /dashboard\r\n\r\n")
        assert looks_like_success(r)

    def test_session_cookie_but_login_redirect_fails(self):
        r = ("HTTP/1.1 302 Found\r\n"
             "Set-Cookie: SESSION=abc\r\n"
             "Location: /login?err=1\r\n\r\n")
        assert not looks_like_success(r)

    def test_error_words_fail(self):
        r = ("HTTP/1.1 200 OK\r\n\r\n"
             "<html>invalid credentials, please try again</html>")
        assert not looks_like_success(r)

    def test_bare_200_with_session_cookie(self):
        r = ("HTTP/1.1 200 OK\r\n"
             "Set-Cookie: sess=abc\r\n\r\n"
             "<html>Welcome</html>")
        assert looks_like_success(r)

    def test_empty_fails(self):
        assert not looks_like_success("")
