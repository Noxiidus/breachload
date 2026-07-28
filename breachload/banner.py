"""Startup banner.

Pure-ASCII art only (no box-drawing / block glyphs) so it renders on every
terminal, including the Windows cp1250 console.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from rich.console import Console

_ART = r"""
 _                         _     _                 _
| |__  _ __ ___  __ _  ___| |__ | | ___   __ _  __| |
| '_ \| '__/ _ \/ _` |/ __| '_ \| |/ _ \ / _` |/ _` |
| |_) | | |  __/ (_| | (__| | | | | (_) | (_| | (_| |
|_.__/|_|  \___|\__,_|\___|_| |_|_|\___/ \__,_|\__,_|
"""


def _version() -> str:
    try:
        return version("breachload")
    except PackageNotFoundError:
        return "dev"


def print_banner(console: Console) -> None:
    console.print(_ART.strip("\n"), style="bold green", markup=False, highlight=False)
    console.print(f"  by Noxidus   //   autonomous pentest copilot   //   v{_version()}",
                  style="bold cyan", markup=False, highlight=False)
    console.print("  authorized testing only - you own the scope",
                  style="dim red", markup=False, highlight=False)
    console.print()
