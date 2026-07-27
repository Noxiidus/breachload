"""PoC generator — offline template and stubbed-Claude paths."""

from breachload.core.state import Finding, Severity
from breachload.exploit.poc import PocGenerator, _extract_code

FINDING = Finding(title="Apache path traversal", severity=Severity.CRITICAL,
                  host="10.10.10.5", service_key="80/tcp", cve=["CVE-2021-41773"],
                  description="Path traversal in Apache 2.4.49.")


class TestOfflineTemplate:
    def test_generates_template_artifact(self, tmp_path):
        gen = PocGenerator()
        gen._client = None                       # force offline regardless of env
        art = gen.generate(FINDING, tmp_path / "artifacts")
        assert art.kind == "poc" and art.tool == "template"
        assert art.format == "python"
        assert art.meta["cve"] == "CVE-2021-41773"
        text = (tmp_path / "artifacts" / art.name).read_text(encoding="utf-8")
        assert "CVE-2021-41773" in text and "sys.argv[1]" in text

    def test_name_slugifies_cve(self, tmp_path):
        gen = PocGenerator()
        gen._client = None
        art = gen.generate(FINDING, tmp_path / "artifacts")
        assert art.name == "poc_CVE_2021_41773.py"


class TestStubbedClaude:
    def test_uses_returned_code(self, tmp_path):
        class _Msg:
            content = [type("B", (), {"text": "```python\nprint('pwn')\n```"})()]

        class _Client:
            class messages:
                @staticmethod
                def create(**kwargs):
                    return _Msg()

        gen = PocGenerator()
        gen._client = _Client()
        art = gen.generate(FINDING, tmp_path / "artifacts")
        assert art.tool == "claude"
        code = (tmp_path / "artifacts" / art.name).read_text(encoding="utf-8").strip()
        assert code == "print('pwn')"

    def test_api_error_falls_back_to_template(self, tmp_path):
        class _Client:
            class messages:
                @staticmethod
                def create(**kwargs):
                    raise RuntimeError("api down")

        gen = PocGenerator()
        gen._client = _Client()
        art = gen.generate(FINDING, tmp_path / "artifacts")
        text = (tmp_path / "artifacts" / art.name).read_text(encoding="utf-8")
        assert "template stub" in text


class TestExtractCode:
    def test_fenced_python(self):
        assert _extract_code("pre\n```python\nx = 1\n```\npost") == "x = 1"

    def test_plain(self):
        assert _extract_code("just code") == "just code"
