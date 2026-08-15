"""Rule-based next-step engine — "autopilot" without an LLM.

Reads the structured state (open services + findings) and emits a prioritized,
copy-paste-ready plan drawn from the offline payload library. This is what makes
breachload useful to someone with no API key: deterministic recommendations of
exactly what to run next and which payload to use.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.state import EngagementState, Service, Severity
from ..exploit.library import PayloadLibrary
from .chains import ChainMatcher

_SEV_PRIORITY = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 3,
    Severity.LOW: 5, Severity.INFO: 6,
}
_HTTP_PORTS = (80, 443, 8080, 8443, 8000)
_HTTPS = (443, 8443)


def _first_cred(state: EngagementState) -> tuple[str, str]:
    """A username/password to auto-fill AD chains; placeholders if none looted."""
    for c in state.credentials:
        if c.username and c.secret and c.kind == "password":
            return c.username, c.secret
    for c in state.credentials:
        if c.username:
            return c.username, c.secret or "<pass>"
    return "<user>", "<pass>"


def _domain_from_state(state: EngagementState) -> str:
    """The AD domain, if the correlator tagged a host with `domain:<x>`."""
    for host in state.hosts.values():
        for tag in host.tags:
            if tag.startswith("domain:"):
                return tag.split(":", 1)[1]
    return "<domain>"


@dataclass
class Suggestion:
    priority: int
    title: str
    why: str
    actions: list[str] = field(default_factory=list)


class SuggestionEngine:
    def __init__(self, library: PayloadLibrary | None = None,
                 chains: ChainMatcher | None = None) -> None:
        self.library = library or PayloadLibrary.default()
        self.chains = chains or ChainMatcher.default()

    def suggest(self, state: EngagementState, lhost: str = "LHOST",
                lport: int = 4444) -> list[Suggestion]:
        out: list[Suggestion] = []
        out += self._from_chains(state, lhost, lport)
        out += self._from_findings(state)
        out += self._from_lateral(state)
        out += self._from_pivot(state, lhost)
        for host in state.hosts.values():
            for svc in host.services.values():
                out += self._from_service(host.address, svc, lhost, lport)
        out.append(self._post_shell(lhost))
        out.sort(key=lambda s: s.priority)
        return out

    def _from_pivot(self, state: EngagementState, lhost: str) -> list[Suggestion]:
        """Two or more hosts in scope means an internal network to tunnel into."""
        if len(state.hosts) < 2:
            return []
        user, _ = _first_cred(state)
        pivot = next(iter(state.hosts))
        ids = ["pivot-chisel-server", "pivot-chisel-client", "pivot-ligolo",
               "pivot-ssh-socks", "pivot-proxychains"]
        actions = [self.library.get(i).render(LHOST=lhost, TARGET=pivot, USER=user)
                   for i in ids if self.library.get(i)]
        return [Suggestion(
            priority=4, title="Pivot to the internal network",
            why=f"{len(state.hosts)} hosts in scope - tunnel through your foothold "
                "to reach the rest",
            actions=actions,
        )]

    def _from_lateral(self, state: EngagementState) -> list[Suggestion]:
        """Credentials are gold: suggest reusing them across hosts and services."""
        usable = [c for c in state.credentials
                  if c.username and (c.secret or c.kind in ("hash", "key"))]
        if not usable:
            return []
        hosts = list(state.hosts)
        target = hosts[0] if hosts else "<target>"
        ports = {s.port for h in state.hosts.values() for s in h.services.values()}
        out = []
        for cred in usable[:3]:
            secret = cred.secret or "<secret>"
            user = cred.username
            if cred.kind == "hash":
                actions = [f"crackmapexec smb {target} -u {user} -H {secret}   # pass-the-hash"]
            else:
                actions = [f"crackmapexec smb {target} -u {user} -p '{secret}'   # validate/spray"]
            if 22 in ports:
                actions.append(f"ssh {cred.username}@{target}")
            if 3389 in ports:
                actions.append(f"xfreerdp /v:{target} /u:{cred.username} /p:'{secret}' +clipboard")
            if len(hosts) > 1:
                actions.append(f"# reuse across all {len(hosts)} hosts (password reuse is common)")
            out.append(Suggestion(
                priority=2, title=f"Lateral movement with {cred.username}",
                why=f"captured {cred.kind} credential — reuse across hosts/services",
                actions=actions,
            ))
        return out

    # --- rules --------------------------------------------------------------
    def _from_chains(self, state: EngagementState, lhost: str, lport: int) -> list[Suggestion]:
        out = []
        user, passwd = _first_cred(state)          # auto-fill AD chains from loot
        domain = _domain_from_state(state)
        for chain in self.chains.match(state):
            target = self.chains.target_for(chain, state)
            out.append(Suggestion(
                priority=chain.priority - 10,   # matched chains outrank ad-hoc steps
                title=f"Chain: {chain.name}",
                why="matched attack-chain template",
                actions=chain.render_steps(TARGET=target, LHOST=lhost, LPORT=lport,
                                           USER=user, PASS=passwd, DOMAIN=domain),
            ))
        return out

    def _from_findings(self, state: EngagementState) -> list[Suggestion]:
        out = []
        for idx, f in enumerate(state.findings):
            if not f.cve:
                continue
            cve = f.cve[0]
            out.append(Suggestion(
                priority=_SEV_PRIORITY.get(f.severity, 6),
                title=f"Exploit: {f.title}",
                why=f"{f.severity.value} finding on {f.host or '?'} ({', '.join(f.cve)})",
                actions=[
                    f"breachload poc <cfg> --index {idx}     # generate a PoC artifact",
                    f"searchsploit {cve}",
                    f"# then: breachload deliver <cfg> --artifact <poc> "
                    f"--target {f.host or '<target>'}",
                ],
            ))
        return out

    def _from_service(self, addr: str, svc: Service, lhost: str, lport: int) -> list[Suggestion]:
        name = (svc.name or "").lower()
        ctx = {"TARGET": addr, "PORT": svc.port, "LHOST": lhost, "LPORT": lport}

        if svc.port == 21 or name == "ftp":
            return [self._svc(2, f"FTP on {addr}", "Check anonymous access and files",
                              ["svc-ftp-anon"], ctx)]
        if svc.port in (139, 445) or name in ("microsoft-ds", "netbios-ssn", "smb"):
            return [self._svc(2, f"SMB on {addr}", "Enumerate shares, users, null sessions",
                              ["svc-smb-null", "svc-smb-enum"], ctx)]
        if svc.port in _HTTP_PORTS or "http" in name:
            return [self._svc(3, f"HTTP on {addr}:{svc.port}",
                              "Content discovery and web-shell paths",
                              ["svc-http-fuzz", "rev-php", "webshell-php"], ctx)]
        if svc.port == 3389 or name == "ms-wbt-server":
            return [self._svc(4, f"RDP on {addr}", "Connect with found credentials",
                              ["svc-rdp"], ctx)]
        return []

    def _post_shell(self, lhost: str) -> Suggestion:
        ctx = {"LHOST": lhost}
        ids = ["tty-python", "enum-sudo", "enum-suid", "enum-caps", "enum-linpeas"]
        return Suggestion(
            priority=8, title="Once you have a shell",
            why="Stabilize the shell, then hunt for a privilege-escalation path",
            actions=[self._render(i, **ctx) for i in ids if self.library.get(i)],
        )

    # --- helpers ------------------------------------------------------------
    def _svc(self, prio: int, title: str, why: str, ids: list[str], ctx: dict) -> Suggestion:
        return Suggestion(prio, title, why,
                          [self._render(i, **ctx) for i in ids if self.library.get(i)])

    def _render(self, payload_id: str, **ctx) -> str:
        payload = self.library.get(payload_id)
        return payload.render(**ctx) if payload else payload_id
