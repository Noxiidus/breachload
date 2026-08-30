"""Minimal, dependency-free PDF writer for reports.

Renders plain text (the Markdown report reads fine as text) into a valid,
multi-page PDF using the built-in Courier font - no fonts to embed, no third-
party libraries, works everywhere. It is intentionally a text PDF, not a styled
layout; the goal is a portable, printable deliverable.
"""

from __future__ import annotations

import textwrap

_PAGE_W, _PAGE_H = 612, 792     # US Letter, points
_MARGIN = 50
_FONT_SIZE = 9
_LEADING = 12
_TOP_Y = _PAGE_H - _MARGIN
_LINES_PER_PAGE = (_PAGE_H - 2 * _MARGIN) // _LEADING
_WRAP = 95


def render_pdf(text: str, title: str = "breachload report") -> bytes:
    lines = _wrap(text)
    pages = _paginate(lines) or [[""]]
    return _assemble(pages)


def _wrap(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        if not raw:
            out.append("")
            continue
        out.extend(textwrap.wrap(raw, width=_WRAP) or [""])
    return out


def _paginate(lines: list[str]) -> list[list[str]]:
    return [lines[i:i + _LINES_PER_PAGE] for i in range(0, len(lines), _LINES_PER_PAGE)]


# --- PDF object assembly ---------------------------------------------------

def _obj(num: int, body: bytes) -> bytes:
    return f"{num} 0 obj\n".encode() + body + b"\nendobj\n"


# Common non-latin-1 punctuation that would otherwise become "?" in the PDF.
_UNICODE_ASCII = str.maketrans({
    "—": "-", "–": "-",      # em / en dash
    "‘": "'", "’": "'",      # curly single quotes
    "“": '"', "”": '"',      # curly double quotes
    "…": "...",                     # ellipsis
    " ": " ",                       # non-breaking space
    "·": "-",                       # middle dot
    "→": "->",                      # right arrow
    "✅": "[OK]", "❔": "[?]",  # emoji that may appear in report text
})


def _escape(line: str) -> bytes:
    b = line.translate(_UNICODE_ASCII).encode("latin-1", "replace")
    return b.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def _content_stream(page_lines: list[str]) -> bytes:
    parts = [b"BT", f"/F1 {_FONT_SIZE} Tf".encode(), f"{_LEADING} TL".encode(),
             f"{_MARGIN} {_TOP_Y} Td".encode()]
    for i, line in enumerate(page_lines):
        if i:
            parts.append(b"T*")
        parts.append(b"(" + _escape(line) + b") Tj")
    parts.append(b"ET")
    return b"\n".join(parts) + b"\n"


def _assemble(pages: list[list[str]]) -> bytes:
    font_num = 3
    body_objs: list[tuple[int, bytes]] = []
    kids: list[str] = []
    next_num = 4
    for page_lines in pages:
        content_num, page_num = next_num, next_num + 1
        next_num += 2
        stream = _content_stream(page_lines)
        content_body = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        body_objs.append((content_num, _obj(content_num, content_body)))
        page_body = (f"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 "
                     f"{font_num} 0 R >> >> /Contents {content_num} 0 R "
                     f"/MediaBox [0 0 {_PAGE_W} {_PAGE_H}] >>").encode()
        body_objs.append((page_num, _obj(page_num, page_body)))
        kids.append(f"{page_num} 0 R")

    catalog = _obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pages_body = (f"<< /Type /Pages /Kids [{' '.join(kids)}] "
                  f"/Count {len(pages)} >>").encode()
    pages_obj = _obj(2, pages_body)
    font_obj = _obj(font_num, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    all_objs = sorted([(1, catalog), (2, pages_obj), (font_num, font_obj), *body_objs])

    out = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for num, data in all_objs:
        offsets[num] = len(out)
        out += data

    xref_pos = len(out)
    size = len(all_objs) + 1
    out += f"xref\n0 {size}\n".encode()
    out += b"0000000000 65535 f \n"
    for num in range(1, size):
        out += f"{offsets[num]:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return bytes(out)
