"""Held-out coverage measurement against real retired-box state.json snapshots.

Marked `held_out`; a normal `pytest` run SKIPS these. Run with:

    pytest -m held_out -v

Each test loads a state.json from `tests/held_out/states/<box>.json` (dogfood
output) and checks the tokens the writeup uses appear somewhere in it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from breachload.analysis.coverage import BoxExpectation, measure, summarize
from breachload.core.state import EngagementState

pytestmark = pytest.mark.held_out

STATES = Path(__file__).parent / "states"

# Each entry names a retired box + the tokens the writeup's primary chain uses.
# Add new entries as dogfood runs land - keep tokens SHORT and CLASS-level, not
# per-box (a good token is "kerberoast" not "svc_sql_super_secret").
EXPECTATIONS = [
    BoxExpectation("forest", "easy", "kerberoast/asrep",
                   ["as-rep", "kerberoast", "dc"]),
    BoxExpectation("sauna", "easy", "asrep-roast",
                   ["as-rep", "dc"]),
    BoxExpectation("active", "easy", "gpp-cpassword",
                   ["gpp", "cpassword", "smb"]),
    BoxExpectation("support", "easy", "adcs-esc1",
                   ["adcs", "esc1"]),
    BoxExpectation("cronos", "medium", "webapp-cve-lead",
                   ["subdomain", "dns"]),
    BoxExpectation("networked", "medium", "upload-bypass",
                   ["upload", "http"]),
    BoxExpectation("cap", "easy", "secret-disclosure",
                   ["capture", "http", "ftp"]),
    BoxExpectation("nibbles", "easy", "default-cred",
                   ["admin", "http"]),
]


def _load(box: str) -> EngagementState | None:
    path = STATES / f"{box}.json"
    if not path.exists():
        return None
    return EngagementState.model_validate_json(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("exp", EXPECTATIONS, ids=lambda e: e.box)
def test_held_out_box_class_surfaced(exp: BoxExpectation):
    state = _load(exp.box)
    if state is None:
        pytest.skip(f"no state.json yet for {exp.box} - run dogfood first")
    result = measure(state, exp)
    assert result.passed, (
        f"{exp.box}: class '{exp.class_ok}' not surfaced. "
        f"Missing tokens: {result.missed_tokens}. "
        f"Hits: {result.hit_tokens}. "
        f"This is the GAP to close - as a class detector, not a per-box patch.")


def test_aggregate_pass_rate_report():
    results = []
    for exp in EXPECTATIONS:
        state = _load(exp.box)
        if state is None:
            continue
        results.append(measure(state, exp))
    if not results:
        pytest.skip("no dogfood state snapshots yet")
    summary = summarize(results)
    # Print for the -v run; also written to a small artifact so a CI report
    # can pick it up later.
    print(f"\nheld-out coverage: {json.dumps(summary, indent=2)}")
    (STATES / "..").resolve().joinpath("last-summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
