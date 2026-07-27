"""nmap adapter — the reference implementation of the adapter pattern.

Runs nmap with XML output and folds hosts/services/versions into state. Parsing
uses nmap's -oX so we never scrape human-readable text.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ..core.state import EngagementState, Service
from ..safety.validator import Risk
from .base import ToolAdapter, ToolResult


@dataclass
class NmapAdapter(ToolAdapter):
    name: str = "nmap"
    binary: str = "nmap"
    risk: Risk = Risk.RECON

    def __post_init__(self) -> None:
        if not self.capabilities:
            self.capabilities = ["port-scan", "service-detection", "os-detection"]

    def build_command(self, target: str, *, ports: str | None = None,
                      service_scan: bool = True, extra: list[str] | None = None) -> list[str]:
        # -oX - streams XML to stdout so parse() gets structured data.
        cmd = ["nmap", "-oX", "-", "-Pn"]
        if service_scan:
            cmd += ["-sV"]
        if ports:
            cmd += ["-p", ports]
        if extra:
            cmd += extra
        cmd.append(target)
        return cmd

    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        notes: list[str] = []
        if not result.stdout.strip().startswith("<?xml"):
            return [f"nmap produced no XML (exit {result.exit_code})"]
        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError as exc:
            return [f"nmap XML parse error: {exc}"]

        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find("address")
            if addr_el is None:
                continue
            address = addr_el.get("addr", "")
            host = state.upsert_host(address)

            for hn in host_el.findall("hostnames/hostname"):
                name = hn.get("name")
                if name and name not in host.hostnames:
                    host.hostnames.append(name)

            os_el = host_el.find("os/osmatch")
            if os_el is not None:
                host.os_guess = os_el.get("name")

            for port_el in host_el.findall("ports/port"):
                st = port_el.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc_el = port_el.find("service")
                svc = Service(
                    port=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", "tcp"),
                    name=svc_el.get("name") if svc_el is not None else None,
                    product=svc_el.get("product") if svc_el is not None else None,
                    version=svc_el.get("version") if svc_el is not None else None,
                )
                host.upsert_service(svc)
                detail = f"{svc.name or '?'} {svc.product or ''}".strip()
                notes.append(f"{address} {svc.key} open: {detail}")

        return notes or ["nmap: no open ports found"]
