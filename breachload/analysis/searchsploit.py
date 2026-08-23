"""searchsploit (Exploit-DB) integration.

The version->CVE KB is curated and small; searchsploit is the exhaustive local
Exploit-DB index. This module turns a service's product+version into a
searchsploit query, parses the JSON results, and folds the hits into one finding
per service carrying the top Exploit-DB titles + a `searchsploit -m` command to
mirror the exploit locally.

Parsing is deterministic and offline-testable (inject a `runner`); the live
search needs the `searchsploit` binary, and degrades gracefully without it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from ..core.state import EngagementState, Finding, Host, Service, Severity

# Product words that add noise to a searchsploit query (they are descriptors, not
# the software name) — dropped so "Apache httpd" -> "apache".
_NOISE = {"httpd", "server", "daemon", "service", "http", "the", "software"}
_RCE_RE = re.compile(r"remote code execution|\brce\b|command execution|metasploit",
                     re.IGNORECASE)


@dataclass
class SploitHit:
    title: str
    edb_id: str
    path: str = ""
    cves: list[str] = field(default_factory=list)


def search_terms(svc: Service) -> str | None:
    """A searchsploit query from a service's product + version, or None."""
    product = (svc.product or "").strip()
    if not product:
        return None
    # searchsploit is case-insensitive; lowercase for a stable, dedup-friendly query.
    words = [w.lower() for w in re.split(r"\s+", product) if w.lower() not in _NOISE]
    name = " ".join(words) or product.lower()
    # First numeric version component keeps the search from being too specific
    # (searchsploit matches substrings; "2.4.49" often misses, "2.4" hits).
    ver = ""
    if svc.version:
        m = re.match(r"(\d+(?:\.\d+)?)", svc.version)
        if m:
            ver = m.group(1)
    return f"{name} {ver}".strip()


def parse_json(text: str) -> list[SploitHit]:
    """Parse `searchsploit -j` JSON into exploit hits."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    hits: list[SploitHit] = []
    for row in data.get("RESULTS_EXPLOIT", []) or []:
        title = (row.get("Title") or "").strip()
        if not title:
            continue
        codes = row.get("Codes") or ""
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE)
        hits.append(SploitHit(
            title=title, edb_id=str(row.get("EDB-ID") or "").strip(),
            path=(row.get("Path") or "").strip(),
            cves=[c.upper() for c in cves],
        ))
    return hits


def _finding(host: Host, svc: Service, query: str, hits: list[SploitHit]) -> Finding:
    top = hits[:8]
    sev = Severity.HIGH if any(_RCE_RE.search(h.title) for h in top) else Severity.MEDIUM
    lines = [f"[{h.edb_id or '?'}] {h.title}" for h in top]
    cves = sorted({c for h in top for c in h.cves})
    first_id = next((h.edb_id for h in top if h.edb_id), None)
    exploit = f"searchsploit -m {first_id}   # mirror the exploit locally" if first_id else ""
    return Finding(
        title=f"Exploit-DB matches for {svc.product} on {host.address}:{svc.port}",
        severity=sev, host=host.address, service_key=svc.key,
        description=f"searchsploit '{query}' returned {len(hits)} Exploit-DB entr"
                    f"{'y' if len(hits) == 1 else 'ies'}. Review for a matching version.",
        evidence="\n".join(lines), cve=cves, exploit=exploit,
        remediation="Patch the affected service to a fixed version.",
    )


def run_search(state: EngagementState, runner=None) -> list[Finding]:
    """Search Exploit-DB for every versioned service and return findings.

    `runner(argv) -> json_text` is injectable for tests; the default shells out to
    searchsploit. Without the binary (and no runner) it returns nothing.
    """
    if runner is None and shutil.which("searchsploit") is None:
        return []
    runner = runner or _default_runner
    out: list[Finding] = []
    seen: set[str] = set()
    for host in state.hosts.values():
        for svc in host.services.values():
            query = search_terms(svc)
            if not query or query in seen:
                continue
            seen.add(query)
            hits = parse_json(runner(["searchsploit", "-j", *query.split()]))
            if hits:
                out.append(_finding(host, svc, query, hits))
    return out


def _default_runner(argv: list[str]) -> str:  # pragma: no cover - real subprocess
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""
