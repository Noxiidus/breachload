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


def render_markdown(state: EngagementState, *, audit_path=None) -> str:
    out: list[str] = []
    out += _header(state)
    out += _summary(state)
    out += _attack_path(state)
    out += _hosts(state)
    out += _findings(state)
    out += _credentials(state)
    out += _artifacts(state)
    out += _timeline(state)
    out += _audit_integrity(audit_path)
    return "\n".join(out).rstrip() + "\n"


def _audit_integrity(audit_path) -> list[str]:
    """A tamper-evidence statement from the audit hash chain, if the log exists."""
    if not audit_path:
        return []
    from pathlib import Path

    from ..safety.audit import verify_chain
    res = verify_chain(Path(audit_path))
    if res.records == 0:
        return []
    status = ("intact — no tampering detected" if res.ok
              else f"BROKEN at line {res.broken_at} ({res.detail})")
    return ["## Audit integrity", "",
            f"- Records: **{res.records}**",
            f"- Hash chain: **{status}**",
            "", "*Each audit record is SHA-256-chained to the previous one; any "
            "post-hoc edit or deletion breaks the chain.*", ""]


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
    confirmed = sum(1 for f in state.findings if f.validation == "confirmed")
    return [
        "## Summary",
        "",
        f"- Hosts: **{len(state.hosts)}**",
        f"- Open services: **{sum(len(h.services) for h in state.hosts.values())}**",
        f"- Findings: **{len(state.findings)}** ({sev_line})",
        f"- Confirmed (proven): **{confirmed}** · suspected: "
        f"**{len(state.findings) - confirmed}**",
        f"- Credentials: **{len(state.credentials)}**",
        f"- Artifacts: **{len(state.artifacts)}**",
        "",
    ]


def _attack_path(state: EngagementState) -> list[str]:
    """A plain-language narrative of the engagement so far — a study document, not
    just a data dump. Deterministic prose synthesised from state."""
    if not state.hosts and not state.findings:
        return []
    sev_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    out = ["## Attack path", ""]

    # Recon.
    n_hosts = len(state.hosts)
    n_svc = sum(len(h.services) for h in state.hosts.values())
    if n_hosts:
        webhosts = [h.address for h in state.hosts.values()
                    if any(s.port in (80, 443, 8080, 8443, 8000, 3000)
                           for s in h.services.values())]
        line = (f"Recon mapped **{n_hosts} host{'s' if n_hosts != 1 else ''}** with "
                f"**{n_svc} open service{'s' if n_svc != 1 else ''}**.")
        if webhosts:
            line += f" Web surface on: {', '.join(webhosts[:5])}."
        out.append(line)

    # Foothold candidates: the most severe findings that carry a CVE or an exploit.
    leads = sorted((f for f in state.findings if f.cve or f.exploit),
                   key=lambda f: sev_rank.get(f.severity, 9))
    if leads:
        out.append("")
        out.append("Most promising foothold leads:")
        for f in leads[:5]:
            where = f" on {f.host}" if f.host else ""
            cve = f" ({', '.join(f.cve)})" if f.cve else ""
            out.append(f"- **[{f.severity.value.upper()}]** {f.title}{where}{cve}")

    # Credentials & privesc.
    if state.credentials:
        kinds = ", ".join(sorted({c.kind for c in state.credentials}))
        out.append("")
        out.append(f"Collected **{len(state.credentials)} credential(s)** ({kinds}) — "
                   "reuse them across hosts/services and for privilege escalation.")
    privesc = [f for f in state.findings
               if any(w in f.title.lower() for w in ("privilege", "privesc", "suid",
                                                     "sudo", "kernel", "group", "token"))]
    if privesc:
        out.append("")
        out.append("Privilege-escalation leads: "
                   + ", ".join(f.title for f in privesc[:5]) + ".")

    # Outcome.
    if state.flags:
        out.append("")
        out.append(f"**Captured {len(state.flags)} flag(s).**")
    out.append("")
    return out


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
    from .scoring import score_label
    loc = " · ".join(x for x in (f.host, f.service_key) if x)
    badge = "✅ CONFIRMED" if f.validation == "confirmed" else "❔ suspected"
    out = [f"### [{f.severity.value.upper()}] {f.title}", ""]
    out.append(f"**Status:** {badge}  ")
    out.append(f"**CVSS:** {score_label(f)}  ")
    if f.validation == "confirmed" and f.proof:
        out.append(f"**Proof:** {f.proof}  ")
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
