"""Hash identification + crack-command generation, with an optional live run.

A recurring HTB foothold mechanic: leak a hash (a DB row, a config, /etc/shadow),
crack it, reuse the plaintext. This module identifies a hash's type, maps it to
the right hashcat mode and john format, and builds ready rockyou commands. It can
also *run* hashcat/john when present and feed the cracked plaintext back into the
engagement (credential reuse then flows through the existing lateral-movement
suggestions).

Identification is deterministic and offline (prefix + shape). The crack itself is
the only optional external step; without hashcat/john installed the module still
prints the exact commands to run by hand.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"


@dataclass
class HashType:
    name: str
    hashcat_mode: str | None      # -m value, None if hashcat has no clean mode
    john_format: str | None       # --format value


# Ordered most-specific first: a prefixed hash ($2b$, $6$, ...) is unambiguous, so
# it must win before the length-based fallbacks (a 32-hex could be MD5 or NTLM).
_PREFIX_TYPES: list[tuple[re.Pattern, HashType]] = [
    (re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$"),
     HashType("bcrypt", "3200", "bcrypt")),
    (re.compile(r"^\$6\$"), HashType("sha512crypt", "1800", "sha512crypt")),
    (re.compile(r"^\$5\$"), HashType("sha256crypt", "7400", "sha256crypt")),
    (re.compile(r"^\$1\$"), HashType("md5crypt", "500", "md5crypt")),
    (re.compile(r"^\$y\$"), HashType("yescrypt", None, "crypt")),
    (re.compile(r"^\$argon2"), HashType("argon2", None, "argon2")),
    (re.compile(r"^\$apr1\$"), HashType("apache-md5", "1600", "md5crypt-apache")),
    (re.compile(r"^\{SSHA\}"), HashType("ssha (LDAP)", "111", "ssha")),
    (re.compile(r"^sha1\$"), HashType("django-sha1", "124", "django")),
    (re.compile(r"^\$P\$|^\$H\$"), HashType("phpass (WordPress/Joomla)", "400", "phpass")),
    (re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"), HashType("NTLMv1-ish/pair", None, None)),
]

# Length-based fallbacks for bare hex digests. NTLM and MD5 share 32 hex, so we
# report both candidates rather than guessing.
_HEX_LEN_TYPES = {
    32: [HashType("MD5", "0", "raw-md5"), HashType("NTLM", "1000", "nt")],
    40: [HashType("SHA1", "100", "raw-sha1")],
    56: [HashType("SHA224", "1300", "raw-sha224")],
    64: [HashType("SHA256", "1400", "raw-sha256")],
    96: [HashType("SHA384", "10800", "raw-sha384")],
    128: [HashType("SHA512", "1700", "raw-sha512")],
}

# Structured formats recognised by shape (contain ':' fields).
_NETNTLM_RE = re.compile(r"^[^:]+::[^:]+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:")   # NetNTLMv2
_KRB5_RE = re.compile(r"^\$krb5(tgs|asrep)\$")


def identify(h: str) -> list[HashType]:
    """Candidate hash types for a raw hash string, best guess first. Empty if
    it doesn't look like a hash we know."""
    h = h.strip()
    if not h:
        return []
    if _KRB5_RE.match(h):
        mode = "13100" if "krb5tgs" in h else "18200"
        return [HashType("Kerberos " + h.split("$")[1], mode, "krb5tgs")]
    if _NETNTLM_RE.match(h):
        return [HashType("NetNTLMv2", "5600", "netntlmv2")]
    for pattern, ht in _PREFIX_TYPES:
        if pattern.match(h):
            return [ht]
    if re.fullmatch(r"[0-9a-fA-F]+", h) and len(h) in _HEX_LEN_TYPES:
        return list(_HEX_LEN_TYPES[len(h)])
    return []


def crack_commands(h: str, wordlist: str = _ROCKYOU) -> list[str]:
    """Ready hashcat + john commands for the identified hash type(s)."""
    cands = identify(h)
    if not cands:
        return []
    out: list[str] = []
    for ht in cands:
        if ht.hashcat_mode is not None:
            out.append(f"hashcat -m {ht.hashcat_mode} -a 0 <hash-file> {wordlist}   # {ht.name}")
        if ht.john_format is not None:
            out.append(f"john --format={ht.john_format} --wordlist={wordlist} <hash-file>   "
                       f"# {ht.name}")
    return out


@dataclass
class CrackResult:
    cracked: bool
    plaintext: str | None
    hash_type: str
    ran: bool                 # whether an external cracker was actually invoked
    detail: str


def run_hashcat(h: str, wordlist: str = _ROCKYOU, runner=None) -> CrackResult:
    """Attempt a live crack with hashcat (falls back to john), if installed.

    `runner` is injectable for tests: called as runner(argv) -> (returncode, stdout).
    Returns the plaintext on success so the caller can store it as a credential.
    """
    cands = identify(h)
    if not cands:
        return CrackResult(False, None, "unknown", False, "unrecognized hash format")
    ht = next((c for c in cands if c.hashcat_mode is not None), cands[0])
    if ht.hashcat_mode is None:
        return CrackResult(False, None, ht.name, False,
                           "no clean hashcat mode - crack it manually (see crack_commands)")

    # A real crack needs hashcat on PATH; a test supplies its own `runner` and so
    # bypasses that check. Without either, report (don't run) so the caller can
    # fall back to printing the manual commands.
    if runner is None and shutil.which("hashcat") is None:
        return CrackResult(False, None, ht.name, False,
                           "hashcat not installed - use crack_commands() to run by hand")
    runner = runner or _default_runner

    argv = ["hashcat", "-m", ht.hashcat_mode, "-a", "0", h, wordlist,
            "--potfile-disable", "--quiet"]
    code, out = runner(argv)
    plain = _extract_plaintext(out, h)
    if plain is not None:
        return CrackResult(True, plain, ht.name, True, "cracked with hashcat")
    return CrackResult(False, None, ht.name, True, f"hashcat ran, no crack (exit {code})")


def _extract_plaintext(output: str, h: str) -> str | None:
    for line in (output or "").splitlines():
        line = line.rstrip("\n")
        if line.startswith(h + ":"):
            return line[len(h) + 1:]
    return None


def _default_runner(argv: list[str]) -> tuple[int, str]:  # pragma: no cover - real subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    return proc.returncode, proc.stdout
