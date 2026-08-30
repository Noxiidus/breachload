"""FTP adapter - checks for anonymous login and lists the root via curl.

Anonymous FTP is a frequent foothold/loot source. Uses curl (always present) so
no extra dependency. Read-only (list), RECON risk.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import Credential, EngagementState, Finding, Service, Severity
from .base import ToolAdapter, ToolResult


@dataclass
class FtpAdapter(ToolAdapter):
    name: str = "ftp"
    binary: str = "curl"

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["ftp", "enumeration"]

    def build_command(self, target: str, *, port: int = 21) -> list[str]:
        self._target = target
        self._port = port
        # A successful anonymous listing prints the directory; failure is non-zero.
        return ["curl", "-s", "--connect-timeout", "8", "--max-time", "20",
                "--user", "anonymous:anonymous", f"ftp://{target}:{port}/"]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 21)
        # curl exits 0 and prints a listing on success. Distinguish the failure
        # modes so a network problem isn't reported as a login denial: 7 =
        # couldn't connect, 28 = timeout, 67 = FTP login denied.
        if result.exit_code != 0:
            if result.exit_code in (7, 28):
                return [f"ftp: could not connect (exit {result.exit_code})"]
            return [f"ftp: anonymous login denied (exit {result.exit_code})"]

        entries = [ln for ln in (result.stdout or "").splitlines() if ln.strip()]
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="ftp", state="open"))
            state.credentials.append(Credential(
                service_key=f"{target}:{port}/tcp", username="anonymous",
                secret="anonymous", kind="password", source="ftp anonymous login",
                validated=True))
            state.add_finding(Finding(
                title="Anonymous FTP login allowed",
                severity=Severity.MEDIUM, host=target, service_key=f"{port}/tcp",
                description=f"FTP on {port} allows anonymous login "
                            f"({len(entries)} entries in root).",
                evidence="\n".join(entries[:30]),
            ))
        listing = ", ".join(e.split()[-1] for e in entries[:10]) if entries else "(empty)"
        return [f"ftp: anonymous login OK - root: {listing}"]
