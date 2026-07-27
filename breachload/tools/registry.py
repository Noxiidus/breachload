"""Tool registry — the set of adapters breachload knows about.

The validator's binary allowlist is derived from here, so adding a tool in one
place both enables it for the planner and authorizes its binary.
"""

from __future__ import annotations

from .base import ToolAdapter
from .enum4linux import Enum4linuxAdapter
from .ffuf import FfufAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .whatweb import WhatWebAdapter


def default_registry() -> dict[str, ToolAdapter]:
    adapters: list[ToolAdapter] = [
        NmapAdapter(),
        WhatWebAdapter(),
        FfufAdapter(),
        NucleiAdapter(),
        Enum4linuxAdapter(),
        # Next: exploit-side generators (msfvenom + Artifact model).
    ]
    return {a.name: a for a in adapters}


def allowed_binaries(registry: dict[str, ToolAdapter]) -> set[str]:
    return {a.binary for a in registry.values()}
