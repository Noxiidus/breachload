"""Client-side browser analysis (Playwright-free via an injected fake driver)."""

from breachload.analysis.browser import (
    BrowserScan,
    RenderedPage,
    analyze_page,
    has_csrf,
    probe_reflected_xss,
)


class _FakeDriver:
    def __init__(self, pages):
        self.pages = pages          # dict: url -> RenderedPage
        self.default = None

    def render(self, url):
        for key, page in self.pages.items():
            if key in url:
                return page
        return self.default or RenderedPage(url=url)


class TestAnalyzePage:
    def test_login_form_flagged(self):
        page = RenderedPage(url="http://x/login", forms=[
            {"action": "/login", "method": "post",
             "inputs": [{"name": "user", "type": "text"},
                        {"name": "pass", "type": "password"}], "has_csrf": True}])
        titles = [f.title for f in analyze_page(page)]
        assert any("Login/auth form" in t for t in titles)

    def test_csrfless_post_flagged(self):
        page = RenderedPage(url="http://x/", forms=[
            {"action": "/save", "method": "post",
             "inputs": [{"name": "v", "type": "text"}], "has_csrf": False}])
        titles = [f.title for f in analyze_page(page)]
        assert any("without a CSRF token" in t for t in titles)

    def test_csrf_token_suppresses_finding(self):
        page = RenderedPage(url="http://x/", forms=[
            {"action": "/save", "method": "post",
             "inputs": [{"name": "csrf_token", "type": "hidden"}], "has_csrf": True}])
        assert not any("CSRF" in f.title for f in analyze_page(page))

    def test_dom_xss_sink(self):
        page = RenderedPage(url="http://x/",
                            html="<script>el.innerHTML = location.hash</script>")
        assert any("DOM-XSS sink" in f.title for f in analyze_page(page))

    def test_external_script(self):
        page = RenderedPage(url="http://x/",
                            scripts=["https://evil.cdn.com/a.js", "/local.js"])
        f = [x for x in analyze_page(page) if "External script" in x.title]
        assert f and "evil.cdn.com" in f[0].evidence


class TestReflectedXss:
    def test_unescaped_reflection_is_high(self):
        # angle brackets survive raw -> real XSS candidate
        canary_page = RenderedPage(url="http://x/", html="<div><blxss7q3z></div>")
        drv = _FakeDriver({"blxss7q3z": canary_page})
        findings = probe_reflected_xss(drv, "http://x/?q=hi", ["q"])
        assert findings and findings[0].severity.value == "high"
        # exploit is a ready URL with the payload URL-encoded
        assert "%3Cscript%3E" in findings[0].exploit and "q=" in findings[0].exploit

    def test_encoded_reflection_is_low(self):
        # only the HTML-encoded form present -> app escaped it -> low
        page = RenderedPage(url="http://x/", html="<div>&lt;blxss7q3z&gt;</div>")
        drv = _FakeDriver({"blxss7q3z": page})
        findings = probe_reflected_xss(drv, "http://x/?q=hi", ["q"])
        assert findings and findings[0].severity.value == "low"

    def test_no_reflection_no_finding(self):
        page = RenderedPage(url="http://x/", html="<div>nothing</div>")
        drv = _FakeDriver({"blxss7q3z": page})
        assert probe_reflected_xss(drv, "http://x/?q=hi", ["q"]) == []


class TestBrowserScan:
    def test_scan_combines_analysis_and_probe(self):
        base = RenderedPage(url="http://x/?name=hi", forms=[
            {"action": "/login", "method": "post",
             "inputs": [{"name": "p", "type": "password"}], "has_csrf": False}])
        reflected = RenderedPage(url="http://x/", html="<p><blxss7q3z></p>")
        drv = _FakeDriver({"blxss7q3z": reflected})
        drv.default = base
        findings = BrowserScan(drv).scan("http://x/?name=hi")
        titles = [f.title for f in findings]
        assert any("Login/auth" in t for t in titles)
        assert any("Reflected input" in t for t in titles)


class TestHelpers:
    def test_has_csrf(self):
        assert has_csrf([{"name": "authenticity_token"}])
        assert not has_csrf([{"name": "email"}])
