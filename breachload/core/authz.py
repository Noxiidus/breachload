"""Operator authorization for the auto-exploit mode.

The auto-exploit mode removes the per-action confirmation prompt (up to and
including EXPLOIT-class actions) so the engine can drive an engagement
autonomously. That is powerful, so enabling it is gated on an *authorized
operator*: the running user must present an id + token that matches an operators
file kept OUTSIDE the repository.

Honesty about what this is: a local allowlist gates casual/accidental use and,
crucially, records *who* authorized an autonomous run in the audit trail. It is
an authorization control, not tamper-proof DRM - anyone who can edit the source
can bypass a local check. The controls that actually keep the tool bounded to
authorized targets are the **scope allowlist** (off-scope is always hard-blocked,
even in auto-exploit mode) and the **audit log**. This gate adds accountability
on top of those.

Operators file (default ``~/.config/breachload/operators.json``, or the path in
``$BREACHLOAD_OPERATORS``):

    {"operators": [{"id": "alice", "token": "<long-random-secret>", "note": "lead"}]}

The running operator identifies via ``$BREACHLOAD_OPERATOR`` (id) and
``$BREACHLOAD_TOKEN`` (secret). Tokens are compared in constant time.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Operator:
    id: str
    token: str
    note: str = ""


@dataclass
class AuthDecision:
    authorized: bool
    operator: str | None
    reason: str


def _default_operators_path() -> Path:
    env = os.environ.get("BREACHLOAD_OPERATORS")
    if env:
        return Path(env)
    return Path.home() / ".config" / "breachload" / "operators.json"


def load_operators(path: Path | None = None) -> list[Operator]:
    """Load the operator allowlist; missing/invalid file yields an empty list."""
    path = path or _default_operators_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[Operator] = []
    for e in raw.get("operators", []):
        if e.get("id") and e.get("token"):
            out.append(Operator(id=str(e["id"]), token=str(e["token"]),
                                note=str(e.get("note", ""))))
    return out


def authorize_operator(operators: list[Operator] | None = None, *,
                       operator_id: str | None = None,
                       token: str | None = None) -> AuthDecision:
    """Decide whether the current operator may run the auto-exploit mode.

    Reads id/token from the environment when not passed explicitly (tests pass
    them directly). A missing operators file, unknown id, or mismatched token all
    deny - the mode fails closed.
    """
    operators = load_operators() if operators is None else operators
    operator_id = operator_id if operator_id is not None else os.environ.get("BREACHLOAD_OPERATOR")
    token = token if token is not None else os.environ.get("BREACHLOAD_TOKEN")

    if not operators:
        return AuthDecision(False, None,
                            "no operators file (set $BREACHLOAD_OPERATORS or create "
                            "~/.config/breachload/operators.json)")
    if not operator_id or not token:
        return AuthDecision(False, None,
                            "set $BREACHLOAD_OPERATOR and $BREACHLOAD_TOKEN to identify")
    match = next((o for o in operators if o.id == operator_id), None)
    if match is None:
        return AuthDecision(False, None, f"operator '{operator_id}' is not authorized")
    # Constant-time comparison so a wrong token can't be timing-guessed.
    if not hmac.compare_digest(match.token, token):
        return AuthDecision(False, operator_id, "token does not match")
    return AuthDecision(True, operator_id, "authorized")


def gate_auto_exploit(config, operators: list[Operator] | None = None) -> AuthDecision:
    """Combined gate: auto-exploit runs only when the engagement enables it, the
    engagement is attested `authorized`, AND the operator passes the gate.

    Fails closed with a specific reason for each missing condition, so the CLI can
    tell the operator exactly why the mode did not activate.
    """
    if not getattr(config, "auto_exploit", False):
        return AuthDecision(False, None, "auto_exploit is not enabled in the engagement")
    if not getattr(config, "authorized", False):
        return AuthDecision(False, None,
                            "engagement is not marked `authorized: true` (attest that you "
                            "have written permission for this scope)")
    return authorize_operator(operators)
