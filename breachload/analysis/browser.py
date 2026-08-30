"""Client-side / browser analysis - the surface a curl-based scanner can't see.

Modern apps render in the browser: forms, auth flows, DOM sinks, and reflected
input only exist after JavaScript runs. This module drives a headless browser to
render a page and then analyses the *rendered* DOM for client-side attack surface:
login/auth forms, CSRF-tokenless state-changing forms, DOM-XSS sinks, external
(supply-chain) script sources, and reflected-input XSS via a canary probe.

The browser itself is behind an injectable ``driver`` protocol, so the analysis is
pure and fully unit-tested without Playwright. The real driver (``PlaywrightDriver``)
is optional: if Playwright isn't installed, the CLI says so and degrades - it never
crashes the run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.state import Finding, Severity


@dataclass
class RenderedPage:
    url: str
    title: str = ""
    html: str = ""
    forms: list[dict] = field(default_factory=list)   # {action, method, inputs, has_csrf}
    scripts: list[str] = field(default_factory=list)  # script src URLs
    console_errors: list[str] = field(default_factory=list)


class Driver:
    """Protocol: render a URL to a RenderedPage (JS executed)."""
    def render(self, url: str) -> RenderedPage:   # pragma: no cover - interface
        raise NotImplementedError


# The canary carries angle brackets + quotes so we can actually tell whether the
# app reflects them RAW (real XSS candidate) or HTML-encodes them (safe). A plain
# alphanumeric canary can't distinguish the two and would over-report.
_XSS_MARK = "blxss7q3z"
_XSS_CANARY = f"<{_XSS_MARK}>"
_SINK_RE = re.compile(r"(innerHTML|document\.write|eval\(|outerHTML|insertAdjacentHTML|"
                      r"\.src\s*=\s*location|setAttribute\(\s*['\"]on)", re.IGNORECASE)
_CSRF_HINT = re.compile(r"csrf|xsrf|authenticity_token|__requestverificationtoken|_token",
                        re.IGNORECASE)


def analyze_page(page: RenderedPage) -> list[Finding]:
    """Findings from a single rendered page (no probing)."""
    out: list[Finding] = []
    host = _host(page.url)

    for form in page.forms:
        inputs = form.get("inputs", [])
        is_login = any(i.get("type") == "password" for i in inputs)
        method = (form.get("method") or "get").lower()
        if is_login:
            out.append(Finding(
                title="Login/auth form (client-side auth surface)",
                severity=Severity.INFO, host=host,
                description=f"A password form posts to {form.get('action') or '(self)'} "
                            f"via {method.upper()}. Test for weak/default creds, auth "
                            "bypass, and credential-stuffing protections.",
                evidence=_form_ev(form)))
        # State-changing form with no CSRF token.
        if method == "post" and not form.get("has_csrf"):
            out.append(Finding(
                title="POST form without a CSRF token",
                severity=Severity.MEDIUM, host=host,
                description=f"The POST form to {form.get('action') or '(self)'} carries "
                            "no anti-CSRF token - a candidate for cross-site request "
                            "forgery. Verify server-side CSRF protection.",
                evidence=_form_ev(form),
                remediation="Add and validate a per-session anti-CSRF token."))

    # DOM-XSS sinks in inline script.
    if _SINK_RE.search(page.html or ""):
        sinks = sorted({m.group(1) for m in _SINK_RE.finditer(page.html)})
        out.append(Finding(
            title="DOM-XSS sink present in client-side code",
            severity=Severity.LOW, host=host,
            description="The rendered page uses dangerous DOM sinks "
                        f"({', '.join(sinks)}). If any is fed from location/URL/"
                        "postMessage without sanitisation it is DOM-based XSS.",
            evidence=", ".join(sinks)))

    # External (supply-chain) scripts.
    ext = [s for s in page.scripts if _is_external(s, host)]
    if ext:
        out.append(Finding(
            title="External script sources loaded",
            severity=Severity.INFO, host=host,
            description="The page loads scripts from other origins - a supply-chain "
                        "surface. Confirm SRI/pinning on: " + ", ".join(ext[:8]),
            evidence="\n".join(ext[:20])))
    return out


def probe_reflected_xss(driver: Driver, url: str, params: list[str]) -> list[Finding]:
    """For each query param, render with an XSS canary and flag unescaped reflection."""
    out: list[Finding] = []
    host = _host(url)
    for p in params:
        test = _set_param(url, p, _XSS_CANARY)
        page = driver.render(test)
        html = page.html or ""
        # Not reflected at all if even the marker text is absent.
        if _XSS_MARK not in html:
            continue
        # RAW reflection = the angle brackets survived unencoded (`<blxss7q3z>`),
        # i.e. a real XSS candidate. If only the encoded form (`&lt;blxss7q3z&gt;`)
        # is present, the app escaped it — low severity, verify context.
        raw = _XSS_CANARY in html
        sev = Severity.HIGH if raw else Severity.LOW
        out.append(Finding(
            title=f"Reflected input in the DOM via '{p}'",
            severity=sev, host=host,
            description=f"The '{p}' parameter is reflected into the rendered page"
                        + (" unescaped - a strong reflected-XSS candidate; try a "
                           "real payload." if raw else " (encoded - verify context)."),
            evidence=f"canary reflected for {p}={_XSS_CANARY}",
            exploit=f"{_set_param(url, p, '<script>alert(1)</script>')}"))
    return out


@dataclass
class BrowserScan:
    driver: Driver

    def scan(self, url: str) -> list[Finding]:
        page = self.driver.render(url)
        findings = analyze_page(page)
        params = _query_params(page.url) or _query_params(url)
        if params:
            findings += probe_reflected_xss(self.driver, url, params)
        return findings


# --- helpers ----------------------------------------------------------------

def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def _is_external(src: str, host: str) -> bool:
    if not src:
        return False
    if src.startswith("//") or src.startswith("http"):
        return _host(src if "://" in src else "http:" + src) != host
    return False


def _form_ev(form: dict) -> str:
    names = ",".join(i.get("name", "?") for i in form.get("inputs", []))
    return f"action={form.get('action')} method={form.get('method')} inputs=[{names}]"


def _query_params(url: str) -> list[str]:
    from urllib.parse import parse_qs, urlparse
    return list(parse_qs(urlparse(url).query).keys())


def _set_param(url: str, param: str, value: str) -> str:
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[param] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


def has_csrf(inputs: list[dict]) -> bool:
    return any(_CSRF_HINT.search(i.get("name", "") or "") for i in inputs)


class PlaywrightDriver(Driver):   # pragma: no cover - requires the optional browser
    """Real headless-Chromium driver. Import-guarded: Playwright is optional."""
    def __init__(self, timeout_ms: int = 15000) -> None:
        self.timeout_ms = timeout_ms

    def render(self, url: str) -> RenderedPage:
        from playwright.sync_api import sync_playwright
        errors: list[str] = []
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("console", lambda m: errors.append(m.text)
                    if m.type == "error" else None)
            page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")
            html = page.content()
            title = page.title()
            final = page.url
            forms = []
            for fe in page.query_selector_all("form"):
                inputs = [{"name": i.get_attribute("name"),
                           "type": i.get_attribute("type") or "text"}
                          for i in fe.query_selector_all("input,textarea,select")]
                forms.append({"action": fe.get_attribute("action"),
                              "method": (fe.get_attribute("method") or "get"),
                              "inputs": inputs, "has_csrf": has_csrf(inputs)})
            scripts = [s.get_attribute("src") for s in page.query_selector_all("script[src]")
                       if s.get_attribute("src")]
            browser.close()
        return RenderedPage(url=final, title=title, html=html, forms=forms,
                            scripts=scripts, console_errors=errors)


def available() -> bool:
    """Whether the optional Playwright browser backend is importable."""
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False
