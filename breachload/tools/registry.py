"""Tool registry — the set of adapters breachload knows about.

The validator's binary allowlist is derived from here, so adding a tool in one
place both enables it for the planner and authorizes its binary.
"""

from __future__ import annotations

from .base import ToolAdapter
from .nmap import NmapAdapter


def default_registry() -> dict[str, ToolAdapter]:
    adapters: list[ToolAdapter] = [
        NmapAdapter(),
        # Next adapters to add: whatweb, ffuf, nuclei, enum4linux-ng.
    ]
    return {a.name: a for a in adapters}


def allowed_binaries(registry: dict[str, ToolAdapter]) -> set[str]:
    return {a.binary for a in registry.values()}
