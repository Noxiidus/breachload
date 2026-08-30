"""Severity <-> CVSS band helpers for reports.

We never *fabricate* a precise CVSS vector - when a finding carries a real base
score (from the CVE KB) we show it; otherwise we show the qualitative band that the
finding's severity maps to under the CVSS v3.1 rating scale. This keeps the report
honest: a number only when we actually have one, a band otherwise.
"""

from __future__ import annotations

from ..core.state import Finding, Severity

# CVSS v3.1 qualitative rating scale.
_BAND = {
    Severity.CRITICAL: "9.0-10.0 (Critical)",
    Severity.HIGH: "7.0-8.9 (High)",
    Severity.MEDIUM: "4.0-6.9 (Medium)",
    Severity.LOW: "0.1-3.9 (Low)",
    Severity.INFO: "0.0 (None)",
}


def score_label(f: Finding) -> str:
    """A CVSS score string for a finding: the real base score, or the severity band."""
    if f.cvss is not None:
        return f"{f.cvss:.1f}"
    return _BAND.get(f.severity, "-")


def band_for(sev: Severity) -> str:
    return _BAND.get(sev, "-")
