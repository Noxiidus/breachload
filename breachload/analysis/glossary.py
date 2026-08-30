"""Offline glossary - plain-language explanations for `breachload explain`.

A learner shouldn't have to leave the tool to find out what "kerberoast" or "ESC1"
means. Each entry is a short *what it is / why it matters / what breachload does*
triplet plus a "learn more" pointer. Fully offline; lookup is case-insensitive and
matches on aliases and substrings so `explain ssti` and `explain "template
injection"` both work.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Term:
    key: str
    title: str
    what: str
    why: str
    breachload: str
    learn: str = ""
    aliases: list[str] = field(default_factory=list)


_TERMS: list[Term] = [
    Term("ssti", "Server-Side Template Injection",
         "User input is rendered by a server-side template engine (Jinja2, Twig, "
         "Freemarker), so your input becomes template code.",
         "It usually escalates straight to remote code execution on the server.",
         "The web attack-surface probe suggests the {{7*7}}=49 test and per-engine RCE payloads.",
         "HackTricks: SSTI - PayloadsAllTheThings/Server Side Template Injection",
         ["template injection", "jinja2"]),
    Term("sqli", "SQL Injection",
         "Untrusted input is concatenated into a SQL query, letting you change the query.",
         "Auth bypass, data theft, and sometimes file write -> web shell.",
         "Suggested probes: ' OR 1=1-- login bypass, sqlmap, and INTO OUTFILE web shell.",
         "PortSwigger Web Security Academy: SQL injection", ["sql injection"]),
    Term("lfi", "Local File Inclusion / Path Traversal",
         "The app includes a file whose path you control, so you can read (or include) "
         "arbitrary files.",
         "Read /etc/passwd, source, secrets; with log poisoning or php wrappers -> RCE.",
         "Probes: ../../etc/passwd, php://filter base64, and log-poisoning to RCE.",
         "HackTricks: File Inclusion", ["file inclusion", "path traversal"]),
    Term("rce", "Remote Code Execution",
         "You can run commands on the target host.",
         "The goal of most footholds - it gives you a shell.",
         "breachload names the CVE/technique and generates a reviewed command; it never "
         "auto-pops a shell unless the authorized auto-exploit mode is enabled.",
         "", ["code execution", "command execution"]),
    Term("ssrf", "Server-Side Request Forgery",
         "You make the server fetch a URL you choose.",
         "Reach internal services and, in cloud, the metadata endpoint (169.254.169.254) "
         "for role credentials.",
         "Probes include the AWS/GCP IMDS URLs; looted IMDS creds fold into state.",
         "HackTricks: SSRF", []),
    Term("kerberoast", "Kerberoasting",
         "Any domain user can request a service ticket (TGS) for an account with an SPN; "
         "the ticket is encrypted with that account's password hash.",
         "Crack the ticket offline to recover a service-account password.",
         "The ad-kerberoast chain runs GetUserSPNs/nxc and gives you the hashcat -m 13100 line.",
         "HackTricks: Kerberoast", ["kerberoasting"]),
    Term("asrep", "AS-REP Roasting",
         "Accounts with 'do not require pre-auth' hand out an encrypted blob to anyone.",
         "Crack it offline for the account password - no credentials needed first.",
         "The ad-unauth-enum chain runs GetNPUsers; crack with hashcat -m 18200.",
         "HackTricks: AS-REP Roast", ["as-rep", "asreproast"]),
    Term("esc1", "ADCS ESC1",
         "A certificate template lets a low-priv user enroll AND supply their own subject "
         "(SAN).",
         "Request a certificate as Domain Admin, then authenticate with it - full domain "
         "compromise.",
         "The adcs command parses certipy and gives the exact certipy req -upn administrator line.",
         "SpecterOps: Certified Pre-Owned", ["adcs"]),
    Term("esc9", "ADCS ESC9",
         "A template with no security extension lets a controlled account's UPN be swapped to "
         "an admin's before enrolling.",
         "Get a certificate that authenticates as the admin.",
         "The ad-adcs-esc9 chain walks the UPN swap + certipy req + auth steps.",
         "", []),
    Term("shadow-credentials", "Shadow Credentials",
         "Write a key to a victim's msDS-KeyCredentialLink attribute, then PKINIT as them.",
         "Impersonate any account you have write access over - no password reset needed.",
         "The ad-shadow-credentials chain uses certipy shadow / pyWhisker + PKINITtools.",
         "", ["shadowcred", "keycredentiallink"]),
    Term("pth", "Pass-the-Hash",
         "Authenticate with an NTLM hash directly, without knowing the plaintext password.",
         "Reuse a dumped hash across the network without cracking it.",
         "Lateral-movement suggestions render the nxc/impacket -H <hash> commands.",
         "", ["pass-the-hash", "passthehash"]),
    Term("dcsync", "DCSync",
         "With replication rights, ask a Domain Controller to hand over account hashes as if "
         "you were another DC.",
         "Dump every hash in the domain, including krbtgt (-> Golden Ticket).",
         "The ad-privesc-dcsync chain runs impacket-secretsdump.",
         "", []),
    Term("suid", "SUID binary",
         "A file that runs as its owner (often root) regardless of who executes it.",
         "If it's a shell-spawning binary, it's an instant privilege escalation.",
         "loot parses the SUID sweep and cross-references GTFOBins for the exact escalation.",
         "GTFOBins", ["setuid"]),
    Term("gtfobins", "GTFOBins",
         "A catalog of how ordinary Unix binaries can be abused to break out of restricted "
         "shells or escalate privileges.",
         "Turns 'I can run tar as root' into a concrete root shell.",
         "The gtfo command and loot look binaries up offline.",
         "https://gtfobins.github.io", []),
    Term("privesc", "Privilege Escalation",
         "Going from a low-privilege foothold to a higher one (root / SYSTEM).",
         "A shell as www-data isn't the goal; root is.",
         "The privesc/winprivesc playbooks drive linpeas/winPEAS and name the escalation.",
         "", ["privilege escalation"]),
    Term("pivoting", "Pivoting",
         "Routing your traffic through a compromised host to reach an internal network you "
         "can't touch directly.",
         "The rest of the target network only exists behind the first box.",
         "When 2+ machines are in scope, suggestions render chisel/ligolo/ssh tunnel commands.",
         "", ["tunneling"]),
    Term("jwt", "JSON Web Token",
         "A signed token carrying claims (who you are, your role) used for auth.",
         "Weak secrets or the alg:none trick let you forge tokens and become admin.",
         "The web probe suggests alg:none forging and hashcat -m 16500 to crack the secret.",
         "", []),
    Term("reverse-shell", "Reverse Shell",
         "The target connects back to a listener on your box, giving you a shell.",
         "Firewalls usually allow outbound connections, so this beats a bind shell.",
         "The listen command gives you the listener + target one-liners with your IP filled in.",
         "", ["revshell", "reverse shell"]),
    Term("hash-crack", "Hash cracking",
         "Recover a plaintext password from its hash by trying a wordlist.",
         "A leaked hash (DB, /etc/shadow) becomes a usable credential.",
         "The crack command identifies the hash type and gives the hashcat/john rockyou line.",
         "", ["cracking", "hashcat"]),
]

# Build a lookup index over keys + aliases.
_INDEX: dict[str, Term] = {}
for _t in _TERMS:
    for _k in [_t.key, *_t.aliases]:
        _INDEX[_k.lower()] = _t


def lookup(term: str) -> Term | None:
    """Find a glossary entry by key, alias, or substring (case-insensitive)."""
    q = term.strip().lower()
    if q in _INDEX:
        return _INDEX[q]
    # Substring against keys/aliases/titles as a fallback.
    for t in _TERMS:
        hay = " ".join([t.key, t.title.lower(), *t.aliases])
        if q and q in hay:
            return t
    return None


def all_terms() -> list[Term]:
    return list(_TERMS)
