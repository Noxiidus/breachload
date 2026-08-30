"""RPC adapter - dumps the portmapper (rpcinfo) to reveal RPC services.

An exposed portmapper (111) lists the RPC programs and their ports - NFS, mountd,
NIS, rquotad - pointing at the next enumeration step. Read-only (RECON).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.state import EngagementState, Finding, Service, Severity
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult

# rpcinfo -p lines: "program vers proto port service"
_LINE_RE = re.compile(r"^\s*\d+\s+\d+\s+(tcp|udp)\s+\d+\s+(\S+)", re.MULTILINE)


@dataclass
class RpcAdapter(ToolAdapter):
    name: str = "rpc"
    binary: str = "rpcinfo"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["rpc", "enumeration"]

    def build_command(self, target: str, *, port: int = 111) -> list[str]:
        self._target = target
        self._port = port
        return ["rpcinfo", "-p", target]

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        target = getattr(self, "_target", None)
        port = getattr(self, "_port", 111)
        text = result.stdout or ""
        services = sorted({name for _proto, name in _LINE_RE.findall(text)})
        if not services:
            return [f"rpc: no RPC programs listed (exit {result.exit_code})"]
        if target:
            host = state.upsert_host(target)
            host.upsert_service(Service(port=port, name="rpcbind", state="open"))
            has_nfs = any(s in ("nfs", "mountd") for s in services)
            state.add_finding(Finding(
                title="RPC portmapper exposes services",
                severity=Severity.MEDIUM if has_nfs else Severity.INFO,
                host=target, service_key=f"{port}/tcp",
                description=f"rpcinfo lists {len(services)} RPC program(s): "
                            f"{', '.join(services)}."
                            + (" mountd/nfs present - list exports with showmount -e."
                               if has_nfs else ""),
                evidence=", ".join(services),
            ))
        return [f"rpc: {len(services)} program(s): {', '.join(services[:10])}"]
