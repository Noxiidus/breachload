"""Version → CVE mapping.

Maps a discovered service's product/version to known CVEs using a local
knowledge base (`data/vuln_kb.json`). Fully offline. The KB is intentionally a
small curated seed; point `CveMatcher` at a fuller NVD-derived feed with the
same schema to scale it up.

Version comparison is deliberately simple (numeric components), which covers
typical service version strings. It is not a full PEP 440 / SemVer implementation.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from ..core.state import EngagementState, Finding, Severity

_OPS = {
    "==": lambda c: c == 0,
    ">=": lambda c: c >= 0,
    "<=": lambda c: c <= 0,
    ">": lambda c: c > 0,
    "<": lambda c: c < 0,
}
_CONSTRAINT_RE = re.compile(r"^(==|>=|<=|>|<)\s*(.+)$")


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _compare(a: str, b: str) -> int:
    ka, kb = _version_key(a), _version_key(b)
    n = max(len(ka), len(kb))
    ka += (0,) * (n - len(ka))
    kb += (0,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def satisfies(version: str, spec: str) -> bool:
    """True if `version` meets every comma-separated constraint in `spec`."""
    if not version:
        return False
    for part in spec.split(","):
        m = _CONSTRAINT_RE.match(part.strip())
        if not m:
            return False
        op, ref = m.group(1), m.group(2).strip()
        if not _OPS[op](_compare(version, ref)):
            return False
    return True


@dataclass
class CveEntry:
    match: list[str]
    range: str
    cve: str
    severity: str
    name: str


class CveMatcher:
    def __init__(self, entries: list[CveEntry]) -> None:
        self.entries = entries

    @classmethod
    def default(cls) -> CveMatcher:
        """Bundled KB, plus any extra feed pointed to by the ``BREACHLOAD_KB``
        environment variable (e.g. one produced by ``breachload kb-import``)."""
        raw = json.loads(
            resources.files("breachload.data").joinpath("vuln_kb.json").read_text(encoding="utf-8")
        )
        entries = cls._parse(raw)
        extra = os.environ.get("BREACHLOAD_KB")
        if extra and Path(extra).is_file():
            entries += cls._parse(json.loads(Path(extra).read_text(encoding="utf-8")))
        return cls(entries)

    @staticmethod
    def _parse(raw: dict) -> list[CveEntry]:
        return [
            CveEntry(
                match=[t.lower() for t in e["match"]],
                range=e["range"], cve=e["cve"],
                severity=e["severity"], name=e["name"],
            )
            for e in raw.get("entries", [])
        ]

    def findings_for(self, state: EngagementState) -> list[Finding]:
        out: list[Finding] = []
        for host in state.hosts.values():
            for svc in host.services.values():
                if not svc.version:
                    continue
                haystack = f"{svc.product or ''} {svc.name or ''}".lower()
                for e in self.entries:
                    if all(tok in haystack for tok in e.match) and satisfies(svc.version, e.range):
                        out.append(Finding(
                            title=f"{e.name} ({e.cve})",
                            severity=Severity(e.severity),
                            host=host.address,
                            service_key=svc.key,
                            description=f"{svc.product or svc.name} {svc.version} "
                                        f"is affected by {e.cve}.",
                            cve=[e.cve],
                            remediation="Upgrade to a fixed version.",
                        ))
        return out
