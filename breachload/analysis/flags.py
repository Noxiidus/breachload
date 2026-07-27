"""CTF flag detection.

Scans arbitrary tool output for common flag formats and returns the unique
flags found. Deliberately conservative patterns to avoid false positives.
"""

from __future__ import annotations

import re

# Common CTF flag shapes: PREFIX{...}, plus bare flag{...}/FLAG{...}.
_PATTERNS = [
    re.compile(r"\b(?:flag|FLAG|HTB|CTF|picoCTF|THM|root|user)\{[^}\n]{1,120}\}"),
    re.compile(r"\bflag\{[^}\n]{1,120}\}", re.IGNORECASE),
]


def find_flags(text: str) -> list[str]:
    """Return unique flags found in `text`, preserving first-seen order."""
    if not text:
        return []
    seen: dict[str, None] = {}
    for pattern in _PATTERNS:
        for match in pattern.findall(text):
            seen.setdefault(match, None)
    return list(seen)
