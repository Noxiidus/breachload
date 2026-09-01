"""Generalized auth-aware crawl: obtain a session cookie, feed it back to recon.

The single biggest blind spot on web boxes is content behind a login. This module
does two class-level jobs, no per-app code:

1. **Login** - given (url, user, pass), try a small ladder of common form
   shapes and Authorization: Basic to obtain a session cookie or bearer token.
2. **Session-hint extraction** - given a cookie jar / response, extract what
   later requests (ffuf, whatweb, appfinger) should include as headers.

Pure argv builders + response parsing. The actual HTTP goes through curl; the
runner is injectable for tests.
"""

from __future__ import annotations

import re

_COMMON_LOGIN_PATHS = (
    "/login", "/wp-login.php", "/admin/login", "/auth/login",
    "/user/login", "/signin", "/api/login", "/session",
)

# username-field candidates -> password-field candidates
_USER_FIELDS = ("username", "user", "login", "email", "log", "j_username")
_PW_FIELDS = ("password", "pass", "pwd", "j_password")


def login_argv(url: str, username: str, password: str,
               *, user_field: str = "username", pw_field: str = "password",
               cookie_jar: str = "/tmp/bl.cookies") -> list[str]:
    """A single curl POST that stores the session cookie in ``cookie_jar``."""
    return ["curl", "-s", "-i", "-c", cookie_jar, "-L", "--max-time", "15",
            "-X", "POST", "-d", f"{user_field}={username}&{pw_field}={password}",
            url]


def basic_auth_argv(url: str, username: str, password: str) -> list[str]:
    """A GET with HTTP basic auth - the trivial case (Tomcat manager, printers)."""
    return ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-u", f"{username}:{password}", "--max-time", "10", url]


def try_login_ladder(base_url: str, username: str, password: str
                     ) -> list[tuple[str, list[str]]]:
    """(label, curl-argv) pairs to attempt on common login endpoints/field-name pairs.

    The operator (or an outer runner) tries them in order until one returns a
    session cookie / 200 for a protected page. This is a small deterministic
    ladder - no login flow discovery per app.
    """
    out: list[tuple[str, list[str]]] = []
    base = base_url.rstrip("/")
    for path in _COMMON_LOGIN_PATHS:
        url = base + path
        for u_field in _USER_FIELDS:
            for p_field in _PW_FIELDS:
                out.append((f"POST {path} ({u_field}/{p_field})",
                            login_argv(url, username, password,
                                       user_field=u_field, pw_field=p_field)))
    out.append(("HTTP Basic auth on the site root",
                basic_auth_argv(base + "/", username, password)))
    return out


_SET_COOKIE_RE = re.compile(r"^Set-Cookie:\s*([^=]+=[^;\r\n]+)", re.IGNORECASE | re.MULTILINE)
_LOCATION_RE = re.compile(r"^Location:\s*(.+?)$", re.IGNORECASE | re.MULTILINE)
_BEARER_JSON_RE = re.compile(r'"(?:access_token|token|jwt)"\s*:\s*"([^"]+)"')


def extract_session(response: str) -> dict[str, str]:
    """Pull a session cookie / bearer token out of a login response.

    Returns a dict with any of: ``cookie`` (the ``name=value`` best guess),
    ``bearer`` (token string), ``location`` (the redirect the login sent us to,
    useful evidence). Empty when the response holds no session artefacts.
    """
    out: dict[str, str] = {}
    if not response:
        return out
    # Prefer non-tracking cookies. Session-shaped names go first.
    session_hints = ("session", "sess", "phpsessid", "auth", "sid", "token", "jwt")
    cookies: list[str] = []
    for m in _SET_COOKIE_RE.finditer(response):
        cookies.append(m.group(1).strip())
    if cookies:
        session_first = sorted(cookies,
                               key=lambda c: (0 if any(h in c.lower()
                                                       for h in session_hints)
                                              else 1))
        out["cookie"] = session_first[0]
        if len(cookies) > 1:
            out["all_cookies"] = "; ".join(cookies)
    loc = _LOCATION_RE.search(response)
    if loc:
        out["location"] = loc.group(1).strip()
    bearer = _BEARER_JSON_RE.search(response)
    if bearer:
        out["bearer"] = bearer.group(1)
    return out


def looks_like_success(response: str) -> bool:
    """Heuristic: does a login response look like an auth SUCCESS?

    True when we got a Set-Cookie for a session-shaped name AND a redirect that
    isn't back to the login path, OR when a bearer token is returned. Reject
    obvious failure markers ("invalid", "denied", "wrong").
    """
    text = response or ""
    if re.search(r"invalid credentials|access denied|wrong password|"
                 r"authentication failed|login failed", text, re.IGNORECASE):
        return False
    sess = extract_session(text)
    if sess.get("bearer"):
        return True
    if not sess.get("cookie"):
        return False
    loc = (sess.get("location") or "").lower()
    # A redirect BACK to the login/signin page is a strong failure signal even if
    # the app set a fresh session cookie beforehand.
    if loc and ("login" in loc or "signin" in loc):
        return False
    if loc:
        return True
    # No redirect at all: session cookie + a 2xx status = plausible success.
    first = text.splitlines()[0] if text.splitlines() else ""
    m = re.match(r"HTTP/[0-9.]+\s+(\d\d\d)", first)
    return bool(m and 200 <= int(m.group(1)) < 300)
