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

# Modern HTB user.txt / root.txt hold a bare 32-char lowercase-hex token with no
# wrapper. Matching this everywhere would flag every MD5 hash, so it is opt-in:
# enable it only when scanning a known flag file or explicit exploit output.
_BARE_HEX_RE = re.compile(r"\b[0-9a-f]{32}\b")


def find_flags(text: str, *, include_bare_hex: bool = False) -> list[str]:
    """Return unique flags found in `text`, preserving first-seen order.

    Set ``include_bare_hex`` to also capture bare 32-char hex tokens (HTB
    user.txt / root.txt). Off by default because such tokens collide with MD5
    hashes; turn it on only in a trusted context (a flag file, delivery output).
    """
    if not text:
        return []
    seen: dict[str, None] = {}
    patterns = [*_PATTERNS, _BARE_HEX_RE] if include_bare_hex else _PATTERNS
    for pattern in patterns:
        for match in pattern.findall(text):
            seen.setdefault(match, None)
    return list(seen)
