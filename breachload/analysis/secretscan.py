"""Generalized secret scanning + sensitive-content discovery.

Two of the most box-agnostic initial-access wins, neither tied to a specific app:

* **Secret scanning** — a curated regex library that pulls credentials/keys/tokens
  out of ANY text (an HTTP response, a config file, looted output, a JS bundle):
  cloud keys, private keys, JWTs, provider tokens, DB connection URIs, password
  assignments. Every hit is a finding, and the credential-shaped ones become
  `Credential` records for reuse.

* **Sensitive-content discovery** — a list of high-signal paths that leak source
  or secrets when exposed (`.git/`, `.env`, backups, `id_rsa`, actuator/env, VCS
  metadata). Produces ready probe commands; a hit is a finding.

Pure functions over text — no per-app knowledge, works on any target.
"""

from __future__ import annotations

import re

from ..core.state import Credential, Finding, Severity

# name -> (compiled regex, severity, is_credential)
_SECRET_PATTERNS: list[tuple[str, re.Pattern, Severity, bool]] = [
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH, True),
    ("AWS secret access key",
     re.compile(r"(?i)aws.{0,20}?secret.{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"),
     Severity.HIGH, True),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     Severity.HIGH, True),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), Severity.HIGH, True),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH, True),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.MEDIUM, True),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     Severity.MEDIUM, True),
    ("Slack webhook",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), Severity.MEDIUM, False),
    ("DB connection URI",
     re.compile(r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://"
                r"[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+"), Severity.HIGH, True),
    ("Authorization bearer",
     re.compile(r"(?i)authorization:\s*bearer\s+([A-Za-z0-9._\-]{16,})"), Severity.MEDIUM, True),
    ("Password assignment",
     re.compile(r"""(?i)(?:password|passwd|pwd|db_pass|secret)\s*[:=]\s*['"]([^'"\s]{4,64})['"]"""),
     Severity.MEDIUM, True),
    ("Generic API key assignment",
     re.compile(r"""(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['"]([0-9A-Za-z_\-]{16,})['"]"""),
     Severity.MEDIUM, True),
]

# Values that are obviously placeholders, not real secrets (cut false positives).
_PLACEHOLDER = re.compile(r"(?i)^(x+|changeme|password|your[_-]?|example|test|<.*>|\.\.\.|"
                          r"placeholder|redacted|null|none)$")


def scan_secrets(text: str, *, host: str | None = None) -> tuple[list[Finding], list[Credential]]:
    """Findings + credentials for every secret pattern that matches ``text``."""
    findings: list[Finding] = []
    creds: list[Credential] = []
    seen: set[str] = set()
    for name, rex, sev, is_cred in _SECRET_PATTERNS:
        for m in rex.finditer(text or ""):
            hit = m.group(0)
            captured = m.group(1) if m.groups() else hit
            if captured and _PLACEHOLDER.match(captured.strip()):
                continue
            key = f"{name}:{hit[:60]}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"Secret exposed: {name}",
                severity=sev, host=host,
                description=f"A {name} was found in the scanned content. Validate and "
                            "reuse it; rotate if this is a real environment.",
                evidence=hit[:200],
                validation="confirmed", proof=f"matched {name}"))
            if is_cred:
                creds.append(Credential(secret=captured[:200], kind="key" if "key" in
                                        name.lower() or "private" in name.lower()
                                        else "token" if "token" in name.lower()
                                        or "jwt" in name.lower() else "password",
                                        source=f"secret-scan ({name})"))
    return findings, creds


# path -> what it leaks. Probed against a web root; a 200/partial is a finding.
SENSITIVE_PATHS: dict[str, str] = {
    "/.git/HEAD": "exposed git repo -> dump source with git-dumper",
    "/.git/config": "exposed git repo (config) -> git-dumper",
    "/.svn/entries": "exposed svn metadata -> source disclosure",
    "/.env": "app secrets (DB creds, API keys, APP_KEY)",
    "/.env.bak": "backup of app secrets",
    "/config.php.bak": "backup PHP config (often DB creds)",
    "/wp-config.php.bak": "WordPress config backup (DB creds, salts)",
    "/.htpasswd": "basic-auth hashes -> crack",
    "/backup.zip": "site/source backup",
    "/backup.tar.gz": "site/source backup",
    "/.DS_Store": "directory listing leak (enumerate files)",
    "/server-status": "Apache status (requests, internal IPs)",
    "/actuator/env": "Spring Boot actuator env (secrets)",
    "/actuator/heapdump": "Spring Boot heap dump (extract secrets)",
    "/phpinfo.php": "phpinfo disclosure (paths, env)",
    "/.aws/credentials": "AWS credentials file",
    "/id_rsa": "private SSH key",
    "/.ssh/id_rsa": "private SSH key",
}


def content_discovery_commands(base_url: str) -> list[str]:
    """Ready curl probes for the high-signal sensitive paths."""
    base = base_url.rstrip("/")
    cmds = [f"curl -s -o /dev/null -w '%{{http_code}} {p}\\n' {base}{p}"
            for p in SENSITIVE_PATHS]
    cmds.append(f"# if /.git/HEAD is 200: git-dumper {base}/.git/ ./loot-git")
    return cmds


def parse_content_discovery(output: str, base_url: str) -> list[Finding]:
    """Turn 'curl -w %{http_code} <path>' probe output into findings for hits."""
    out: list[Finding] = []
    host = _host(base_url)
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        code, path = int(parts[0]), parts[1]
        note = SENSITIVE_PATHS.get(path)
        if note and code in (200, 206, 301, 302, 401, 403):
            sev = Severity.HIGH if code in (200, 206) else Severity.INFO
            state = "accessible" if code in (200, 206) else f"present (HTTP {code})"
            out.append(Finding(
                title=f"Sensitive path {state}: {path}",
                severity=sev, host=host,
                description=f"{base_url.rstrip('/')}{path} returned HTTP {code} - {note}.",
                evidence=f"HTTP {code} {path}",
                validation="confirmed" if code in (200, 206) else "suspected"))
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url
