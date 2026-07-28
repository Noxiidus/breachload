"""Offline GTFOBins lookup.

Maps a binary you found as SUID or allowed via `sudo -l` to a concrete
privilege-escalation command. Fully offline (`data/gtfobins.json`), so it works
without internet or an API key.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def _db() -> dict[str, dict[str, str]]:
    raw = json.loads(
        resources.files("breachload.data").joinpath("gtfobins.json").read_text(encoding="utf-8")
    )
    return raw.get("binaries", {})


def lookup(binary: str) -> dict[str, str]:
    """Return {'suid': ..., 'sudo': ...} escalation commands for `binary` (may be empty)."""
    return _db().get(_basename(binary).lower(), {})


def known_binaries() -> list[str]:
    return sorted(_db())


def _basename(binary: str) -> str:
    return binary.replace("\\", "/").rsplit("/", 1)[-1]
