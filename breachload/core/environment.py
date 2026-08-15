"""Environment detection.

Reports which external tools and wordlists are actually available, so the agent
(and the operator) can tell up front what will run and what will be skipped.
Pure `shutil.which` / path checks — no execution.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

# Tools the engine or its suggestions rely on, grouped by role.
KNOWN_TOOLS = {
    "recon": ["nmap"],
    "enumeration": ["httpx", "whatweb", "ffuf", "gobuster", "enum4linux-ng", "smbclient"],
    "vuln": ["nuclei", "searchsploit"],
    "exploit": ["msfvenom", "msfconsole", "hydra"],
    "active-directory": ["nxc", "netexec", "bloodhound-python", "certipy",
                         "bloodyAD", "evil-winrm", "kerbrute", "impacket-secretsdump"],
    "shell": ["nc", "ncat", "socat", "python3", "curl", "wget"],
}

COMMON_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/rockyou.txt",
]


@dataclass
class ToolStatus:
    name: str
    role: str
    path: str | None

    @property
    def present(self) -> bool:
        return self.path is not None


def check_tools() -> list[ToolStatus]:
    out: list[ToolStatus] = []
    for role, names in KNOWN_TOOLS.items():
        for name in names:
            out.append(ToolStatus(name=name, role=role, path=shutil.which(name)))
    return out


def check_wordlists() -> list[tuple[str, bool]]:
    return [(w, Path(w).is_file()) for w in COMMON_WORDLISTS]


def available_tools() -> set[str]:
    return {t.name for t in check_tools() if t.present}


def is_available(name: str) -> bool:
    return shutil.which(name) is not None
