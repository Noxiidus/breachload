"""Startup banner."""

from io import StringIO

from rich.console import Console

from breachload.banner import print_banner


def _render() -> str:
    buf = StringIO()
    print_banner(Console(file=buf, width=100, force_terminal=False))
    return buf.getvalue()


class TestBanner:
    def test_renders_brand_and_disclaimer(self):
        out = _render()
        assert "Noxidus" in out
        assert "authorized testing only" in out

    def test_is_pure_ascii(self):
        # Non-ASCII art (box-drawing/block glyphs) crashes the Windows cp1250
        # console — the banner must stay pure ASCII.
        assert _render().isascii()
