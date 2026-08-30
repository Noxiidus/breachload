"""Analyzer - folds CVE matches and correlations into state findings.

Runs after tool output has updated state (typically once per orchestrator step).
Deduplicates so repeated runs are idempotent, and returns only the newly added
findings so the caller can surface them.
"""

from __future__ import annotations

from ..core.state import EngagementState, Finding
from .correlator import Correlator
from .cve import CveMatcher
from .webcve import WebCveMatcher


def _sig(f: Finding) -> tuple:
    return (f.host, f.service_key, f.title, tuple(sorted(f.cve)))


class Analyzer:
    def __init__(self, cve: CveMatcher, correlator: Correlator,
                 webcve: WebCveMatcher | None = None) -> None:
        self.cve = cve
        self.correlator = correlator
        self.webcve = webcve or WebCveMatcher.default()

    @classmethod
    def default(cls) -> Analyzer:
        return cls(CveMatcher.default(), Correlator(), WebCveMatcher.default())

    def analyze(self, state: EngagementState) -> list[Finding]:
        existing = {_sig(f) for f in state.findings}
        added: list[Finding] = []
        candidates = [*self.cve.findings_for(state),
                      *self.webcve.findings_for(state),
                      *self.correlator.findings_for(state)]
        for f in candidates:
            s = _sig(f)
            if s in existing:
                continue
            existing.add(s)
            state.add_finding(f)
            added.append(f)
        return added
