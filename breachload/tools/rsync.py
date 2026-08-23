"""rsync adapter — lists exposed rsync modules (often world-readable/writable).

An unauthenticated rsync daemon (873) frequently exposes modules you can pull from
or push to — a direct file-read/write primitive. Read-only listing here (RECON).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class RsyncAdapter(ToolAdapter):
    name: str = "rsync"
    binary: str = "rsync"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["rsync", "enumeration"]

    def build_command(self, target: str, *, port: int = 873) -> list[str]:
        self._target = target
        self._port = port
        # Listing the bare rsync:// URL returns the module list.
        return ["rsync", "--list-only", "--timeout=10", f"rsync://{target}:{port}/"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 873)
        text = result.stdout or ""
        low = (text + " " + (result.stderr or "")).lower()
        if result.exit_code != 0 and not text.strip():
            if "connection refused" in low or "timeout" in low:
                return [f"rsync: could not connect (exit {result.exit_code})"]
        # Module rows start with the module name in the first column.
        modules = [ln.split()[0] for ln in text.splitlines()
                   if ln.strip() and not ln.startswith(" ")]
        if not modules:
            return [f"rsync: no modules listed (exit {result.exit_code})"]
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="rsync", state="open"))
            state.add_finding(Finding(
                title="Unauthenticated rsync modules exposed",
                severity=Severity.HIGH, host=target, service_key=f"{port}/tcp",
                description=f"rsync on {port} exposes {len(modules)} module(s) without "
                            "auth. Pull them for loot, and test write access (often "
                            "a foothold via a writable web/cron path).",
                evidence=", ".join(modules[:20]),
                exploit=f"rsync -av rsync://{target}:{port}/{modules[0]} ./{modules[0]}",
            ))
        return [f"rsync: {len(modules)} module(s): {', '.join(modules[:10])}"]
