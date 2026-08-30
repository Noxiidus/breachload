"""BloodHound ingestion - turn a collection into AD attack findings.

Parses BloodHound / SharpHound / bloodhound-python JSON (a users.json, groups.json,
computers.json, ...) into findings: kerberoastable and AS-REP-roastable accounts,
unconstrained delegation, and the dangerous outbound ACL edges (GenericAll,
WriteOwner, ...) that BloodHound is really used to find - each with the concrete
follow-up command. Defensive parsing: the schema varies across versions, so
missing keys are skipped, not fatal.
"""

from __future__ import annotations

from ..core.state import Finding, Severity

# ACE rights that grant a takeover primitive over the target principal.
_DANGEROUS_RIGHTS = {
    "genericall": "full control -> reset password / shadow-cred / add to group",
    "genericwrite": "write attributes -> targeted Kerberoast or shadow-cred",
    "writeowner": "take ownership, then grant yourself GenericAll",
    "writedacl": "write the DACL, then grant yourself GenericAll",
    "forcechangepassword": "reset the target's password without knowing the old one",
    "addmember": "add yourself (or a controlled user) to the group",
    "allextendedrights": "extended rights -> DCSync (on a domain) / password reset",
    "owns": "you own the object -> grant yourself GenericAll",
}


def _rows(data: dict) -> list[dict]:
    """The object list from a BloodHound file, tolerant of the key casing.

    Defensive: a malformed export (a non-dict document, or a `data` that isn't a
    list of objects) must yield nothing, not crash the parse.
    """
    if not isinstance(data, dict):
        return []
    rows = data.get("data") or data.get("Data") or []
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def _props(obj: dict) -> dict:
    return obj.get("Properties") or obj.get("properties") or {}


def _name(obj: dict) -> str:
    p = _props(obj)
    return p.get("name") or p.get("Name") or obj.get("ObjectIdentifier") or "?"


def _aces(obj: dict) -> list[dict]:
    return obj.get("Aces") or obj.get("ACEs") or obj.get("aces") or []


def parse_bloodhound(data: dict) -> list[Finding]:
    """Findings from one parsed BloodHound JSON document."""
    out: list[Finding] = []
    for obj in _rows(data):
        name = _name(obj)
        p = {k.lower(): v for k, v in _props(obj).items()}

        if p.get("hasspn"):
            out.append(Finding(
                title=f"Kerberoastable account: {name}", severity=Severity.HIGH,
                description="Account has an SPN - request its TGS and crack it offline.",
                cve=[], exploit=f"impacket-GetUserSPNs <domain>/<user>:<pass> -request "
                                f"-dc-ip <dc>   # target {name}; then hashcat -m 13100"))
        if p.get("dontreqpreauth"):
            out.append(Finding(
                title=f"AS-REP roastable account: {name}", severity=Severity.HIGH,
                description="Pre-auth not required - grab the AS-REP and crack it.",
                exploit=f"impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass "
                        f"-dc-ip <dc>   # {name}; then hashcat -m 18200"))
        if p.get("unconstraineddelegation"):
            out.append(Finding(
                title=f"Unconstrained delegation: {name}", severity=Severity.HIGH,
                description="Coerce a DC to authenticate here, capture its TGT -> DCSync.",
                exploit="use printerbug/petitpotam to coerce, then extract the TGT"))

        for ace in _aces(obj):
            right = str(ace.get("RightName") or ace.get("rightname") or "").lower()
            note = _DANGEROUS_RIGHTS.get(right)
            if not note:
                continue
            principal = ace.get("PrincipalSID") or ace.get("principalsid") or "?"
            out.append(Finding(
                title=f"ACL: {right} over {name}", severity=Severity.HIGH,
                description=f"A principal ({principal}) has {right} over {name}: {note}.",
                exploit=f"bloodyAD --host <dc> -d <domain> -u <you> -p <pass> "
                        f"add genericAll {name} <you>   # or the {right}-specific action"))
    return out
