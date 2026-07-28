"""Tool registry — the set of adapters breachload knows about.

The validator's binary allowlist is derived from here, so adding a tool in one
place both enables it for the planner and authorizes its binary.

Third parties can add adapters without patching breachload by registering an
entry point in the ``breachload.tools`` group whose object is a ``ToolAdapter``
subclass (or a zero-arg callable returning one/a list of them):

    [project.entry-points."breachload.tools"]
    my_scanner = "my_pkg.adapters:MyScannerAdapter"
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from .base import ToolAdapter
from .enum4linux import Enum4linuxAdapter
from .ffuf import FfufAdapter
from .httpx import HttpxAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .whatweb import WhatWebAdapter

_log = logging.getLogger(__name__)
_ENTRY_POINT_GROUP = "breachload.tools"


def default_registry(load_plugins: bool = True) -> dict[str, ToolAdapter]:
    adapters: list[ToolAdapter] = [
        NmapAdapter(),
        WhatWebAdapter(),
        HttpxAdapter(),
        FfufAdapter(),
        NucleiAdapter(),
        Enum4linuxAdapter(),
    ]
    registry = {a.name: a for a in adapters}
    if load_plugins:
        merge_plugins(registry)
    return registry


def merge_plugins(registry: dict[str, ToolAdapter]) -> dict[str, ToolAdapter]:
    """Discover and add adapters registered under the ``breachload.tools`` group.

    A broken or malicious plugin must not take down the core, so each entry point
    is loaded defensively; failures are logged and skipped. Built-in adapters are
    never overridden by a plugin of the same name.
    """
    for ep in _plugin_entry_points():
        try:
            for adapter in _as_adapters(ep.load()):
                if adapter.name in registry:
                    _log.warning("plugin adapter %r shadows a built-in; ignoring", adapter.name)
                    continue
                registry[adapter.name] = adapter
        except Exception:  # noqa: BLE001 — one bad plugin must not crash the tool
            _log.exception("failed to load tool plugin %r", getattr(ep, "name", "?"))
    return registry


def _plugin_entry_points():
    try:
        return entry_points(group=_ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover - Python <3.10 selection API
        return entry_points().get(_ENTRY_POINT_GROUP, [])


def _as_adapters(obj) -> list[ToolAdapter]:
    if callable(obj) and not isinstance(obj, ToolAdapter):
        obj = obj()
    items = obj if isinstance(obj, (list, tuple)) else [obj]
    return [a for a in items if isinstance(a, ToolAdapter)]


def allowed_binaries(registry: dict[str, ToolAdapter]) -> set[str]:
    return {a.binary for a in registry.values()}
