"""PDF export — validate the hand-built PDF structure."""

import re

from breachload.report.pdf import render_pdf


def _xref_offsets(pdf: bytes) -> list[int]:
    tail = pdf[pdf.rindex(b"xref"):]
    return [int(m) for m in re.findall(rb"^(\d{10}) 00000 n", tail, re.MULTILINE)]


class TestRenderPdf:
    def test_basic_structure(self):
        pdf = render_pdf("Hello report\n\nSection\n- item")
        assert pdf.startswith(b"%PDF-1.4")
        assert pdf.rstrip().endswith(b"%%EOF")
        assert b"/Type /Catalog" in pdf
        assert b"/Type /Pages" in pdf
        assert b"/BaseFont /Courier" in pdf

    def test_xref_offsets_point_at_objects(self):
        pdf = render_pdf("line one\nline two")
        for num, off in enumerate(_xref_offsets(pdf), start=1):
            assert pdf[off:off + 16].startswith(f"{num} 0 obj".encode())

    def test_multipage(self):
        text = "\n".join(f"line {i}" for i in range(200))
        pdf = render_pdf(text)
        assert pdf.count(b"/Type /Page ") >= 2   # more than one page object

    def test_escapes_parentheses_and_backslashes(self):
        pdf = render_pdf("weird (chars) and a \\ backslash")
        assert rb"\(chars\)" in pdf
        assert rb"\\ backslash" in pdf

    def test_non_latin1_does_not_crash(self):
        pdf = render_pdf("arrow → and dash — and emoji 🎯")
        assert pdf.startswith(b"%PDF-1.4")

    def test_common_punctuation_becomes_ascii(self):
        # em/en dash, curly quotes and ellipsis would render as "?" otherwise.
        pdf = render_pdf("dash — and … dots and “curly” ‘quotes’")
        assert b"dash - and ... dots" in pdf
        assert b'"curly"' in pdf and b"'quotes'" in pdf

    def test_empty_input(self):
        pdf = render_pdf("")
        assert pdf.startswith(b"%PDF-1.4") and b"/Type /Page " in pdf
