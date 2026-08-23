"""Report generation.

Renders the structured engagement state into a Markdown report: an executive
summary, host/service inventory, findings ordered by severity, collected
credentials, generated artifacts, and an activity timeline from the audit-worthy
action history. Plain-Python string building — no template engine dependency.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime

from ..core.state import EngagementState, Finding, Severity

# High → low, for ordering and summary display.
_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


def _cell(value: object) -> str:
    """Sanitize a value for a Markdown table cell: escape pipes and flatten newlines
    so a secret/product/banner containing ``|`` can't break the table."""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render_markdown(state: EngagementState) -> str:
    out: list[str] = []
    out += _header(state)
    out += _summary(state)
    out += _hosts(state)
    out += _findings(state)
    out += _credentials(state)
    out += _artifacts(state)
    out += _timeline(state)
    return "\n".join(out).rstrip() + "\n"


def _header(state: EngagementState) -> list[str]:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return [
        f"# Engagement report — {state.name}",
        "",
        f"*Generated {now} · phase reached: {state.phase.value}*",
        "",
    ]


def _summary(state: EngagementState) -> list[str]:
    counts = Counter(f.severity for f in state.findings)
    parts = [f"{counts[s]} {s.value}" for s in _SEVERITY_ORDER if counts[s]]
    sev_line = ", ".join(parts) if parts else "no findings"
    return [
        "## Summary",
        "",
        f"- Hosts: **{len(state.hosts)}**",
        f"- Open services: **{sum(len(h.services) for h in state.hosts.values())}**",
        f"- Findings: **{len(state.findings)}** ({sev_line})",
        f"- Credentials: **{len(state.credentials)}**",
        f"- Artifacts: **{len(state.artifacts)}**",
        "",
    ]


def _hosts(state: EngagementState) -> list[str]:
    if not state.hosts:
        return []
    out = ["## Hosts & services", "", "| Host | OS | Port | Service | Version |",
           "|------|----|------|---------|---------|"]
    for host in state.hosts.values():
        os_ = _cell(host.os_guess or "?")
        addr = _cell(host.address)
        if not host.services:
            out.append(f"| {addr} | {os_} | — | — | — |")
            continue
        for svc in sorted(host.services.values(), key=lambda s: s.port):
            product = _cell(" ".join(x for x in (svc.product, svc.version) if x) or "—")
            out.append(f"| {addr} | {os_} | {svc.key} | {_cell(svc.name or '?')} | {product} |")
    out.append("")
    return out


def _findings(state: EngagementState) -> list[str]:
    if not state.findings:
        return []
    out = ["## Findings", ""]
    ordered = sorted(state.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))
    for f in ordered:
        out += _finding_block(f, state)
    return out


def _finding_block(f: Finding, state: EngagementState) -> list[str]:
    loc = " · ".join(x for x in (f.host, f.service_key) if x)
    out = [f"### [{f.severity.value.upper()}] {f.title}", ""]
    if loc:
        out.append(f"**Location:** {loc}  ")
    if f.cve:
        out.append(f"**CVE:** {', '.join(f.cve)}  ")
    if f.description:
        out += ["", f.description]
    if f.exploit:
        out += ["", "**Guided exploit** (review before running - confirm-gated):",
                "", "```", f.exploit.strip(), "```"]
    if f.remediation:
        out += ["", f"**Remediation:** {f.remediation}"]
    if f.evidence:
        out += ["", "```", f.evidence.strip()[:1500], "```"]
    repro = _repro_steps(f, state)
    if repro:
        out += ["", "**Reproduce:**", "", "```"] + repro + ["```"]
    out.append("")
    return out


def _repro_steps(f: Finding, state: EngagementState) -> list[str]:
    """Successful commands from the history that targeted this finding's host."""
    if not f.host:
        return []
    # Adjacent-digit guard on both sides so host 10.10.10.5 matches neither
    # 10.10.10.50 (trailing) nor 210.10.10.5 (leading) — the same prefix-collision
    # fix state.has_action uses, applied identically here.
    host_re = re.compile(r"(?<!\d)" + re.escape(f.host) + r"(?!\d)")
    steps = [
        _render_command(a.command)
        for a in state.history
        if a.approved and a.exit_code in (0, None)
        and any(host_re.search(token) for token in a.command)
    ]
    # De-duplicate while preserving order, cap the list.
    seen: dict[str, None] = {}
    for s in steps:
        seen.setdefault(s, None)
    return list(seen)[:5]


def _credentials(state: EngagementState) -> list[str]:
    if not state.credentials:
        return []
    out = ["## Credentials", "", "| Username | Secret | Kind | Service | Validated |",
           "|----------|--------|------|---------|-----------|"]
    for c in state.credentials:
        out.append(
            f"| {_cell(c.username or '—')} | {_cell(c.secret or '—')} | {_cell(c.kind)} | "
            f"{_cell(c.service_key or '—')} | {'yes' if c.validated else 'no'} |"
        )
    out.append("")
    return out


def _artifacts(state: EngagementState) -> list[str]:
    if not state.artifacts:
        return []
    out = ["## Generated artifacts", "", "| Name | Kind | Tool | Platform | Path |",
           "|------|------|------|----------|------|"]
    for a in state.artifacts:
        out.append(
            f"| {_cell(a.name)} | {_cell(a.kind)} | {_cell(a.tool or '—')} | "
            f"{_cell(a.platform or '—')} | {_cell(a.path or '—')} |"
        )
    out.append("")
    return out


def _render_command(command: list[str]) -> str:
    """Join an argv for display, rendering the internal {OUTFILE} tool-managed
    placeholder as a readable path so shown commands are copy-paste-ready."""
    return " ".join(command).replace("{OUTFILE}", "output.json")


def _timeline(state: EngagementState) -> list[str]:
    if not state.history:
        return []
    out = ["## Activity timeline", ""]
    for a in state.history:
        status = "blocked/skipped" if not a.approved else f"exit {a.exit_code}"
        out.append(f"- `{a.phase.value}` **{a.tool}** — {_render_command(a.command)} ({status})")
    out.append("")
    return out
