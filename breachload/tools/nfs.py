"""NFS adapter - lists exported shares via `showmount -e`.

Exported NFS shares (especially world-readable or `no_root_squash`) are a common
foothold/loot vector. Read-only enumeration, RECON risk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from .base import ToolAdapter, ToolResult

_EXPORT_RE = re.compile(r"^(/\S+)\s+(.*)$")


@dataclass
class NfsAdapter(ToolAdapter):
    name: str = "nfs"
    binary: str = "showmount"

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["nfs", "enumeration"]

    def build_command(self, target: str, *, port: int = 2049) -> list[str]:
        self._target = target
        self._port = port
        return ["showmount", "-e", "--no-headers", target]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 2049)
        text = result.stdout or ""
        exports: list[tuple[str, str]] = []
        for ln in text.splitlines():
            m = _EXPORT_RE.match(ln.strip())
            if m:
                exports.append((m.group(1), m.group(2).strip()))
        if not exports:
            return [f"nfs: no exports (exit {result.exit_code})"]

        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="nfs", state="open"))
            for path, allowed in exports:
                # An export allowing everyone (`*`) is the noteworthy case.
                sev = Severity.MEDIUM if "*" in allowed else Severity.LOW
                state.add_finding(Finding(
                    title=f"NFS export: {path}",
                    severity=sev, host=target, service_key=f"{port}/tcp",
                    description=f"NFS share {path} exported to '{allowed or 'unspecified'}'. "
                                "Mount it to read/write files; check for no_root_squash.",
                    evidence=f"{path} {allowed}",
                ))
        return [f"nfs export {p} -> {a or '*'}" for p, a in exports]
