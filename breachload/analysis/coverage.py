"""Held-out coverage measurement for retired-box regressions.

The technique-coverage doc is only meaningful if we MEASURE how often the
current build actually surfaces the right lead on unseen boxes. This module
encodes each held-out box as a small list of "expected" tokens (substrings that
must appear in the state - finding titles, service notes, credentials) and
returns a coverage percentage.

Pure function over state; no network. Tests live in `tests/held_out/`, marked
`held_out` so a normal pytest run skips them (opt in with `-m held_out`) and
they never gate CI.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.state import EngagementState


@dataclass
class BoxExpectation:
    box: str
    difficulty: str                     # easy | medium | hard | insane
    class_ok: str                       # the technique CLASS we want covered
    tokens: list[str]                   # substrings that must appear SOMEWHERE
    # Optional refinement: score partial if only a subset of tokens hit.
    require_all: bool = False


@dataclass
class CoverageResult:
    box: str
    difficulty: str
    class_ok: str
    hit_tokens: list[str]
    missed_tokens: list[str]

    @property
    def score(self) -> float:
        total = len(self.hit_tokens) + len(self.missed_tokens)
        return len(self.hit_tokens) / total if total else 0.0

    @property
    def passed(self) -> bool:
        # A box "passes" if we hit at least one expected token (partial credit
        # counts - we're measuring *did the class surface at all*, not perfection).
        return len(self.hit_tokens) > 0


def _state_haystack(state: EngagementState) -> str:
    """A single lowercased blob of every user-facing surface in the state.

    Everything an operator would read - service notes/products/banners, finding
    titles/descriptions/CVEs, credential usernames/sources, host tags - is
    included, so a "did we surface this?" test is a plain substring check.
    """
    parts: list[str] = []
    for host in state.hosts.values():
        parts.append(host.address)
        parts.extend(host.tags)
        for svc in host.services.values():
            parts += [svc.name or "", svc.product or "", svc.banner or "",
                      *svc.notes]
    for f in state.findings:
        parts += [f.title, f.description, " ".join(f.cve)]
    for c in state.credentials:
        parts += [c.username or "", c.source or ""]
    return " ".join(parts).lower()


def measure(state: EngagementState, expectation: BoxExpectation) -> CoverageResult:
    """Score one box's held-out expectations against a real state.json."""
    hay = _state_haystack(state)
    hit: list[str] = []
    missed: list[str] = []
    for tok in expectation.tokens:
        (hit if tok.lower() in hay else missed).append(tok)
    return CoverageResult(box=expectation.box, difficulty=expectation.difficulty,
                          class_ok=expectation.class_ok, hit_tokens=hit,
                          missed_tokens=missed)


def summarize(results: list[CoverageResult]) -> dict:
    """Aggregate held-out results into per-difficulty + per-class rates."""
    by_diff: dict[str, list[CoverageResult]] = {}
    by_class: dict[str, list[CoverageResult]] = {}
    for r in results:
        by_diff.setdefault(r.difficulty, []).append(r)
        by_class.setdefault(r.class_ok, []).append(r)

    def _pct(items: list[CoverageResult]) -> float:
        return round(sum(i.passed for i in items) / len(items) * 100, 1) if items else 0.0

    return {
        "total": len(results),
        "passed": sum(r.passed for r in results),
        "overall_pass_rate": _pct(results),
        "by_difficulty": {k: _pct(v) for k, v in by_diff.items()},
        "by_class": {k: _pct(v) for k, v in by_class.items()},
        "avg_score": round(sum(r.score for r in results) / len(results), 3)
        if results else 0.0,
    }
