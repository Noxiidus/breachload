"""Self-contained HTML report renderer.

The Markdown report (`engine.render_markdown`) is the machine-diffable record; this
is the shareable one — a single styled HTML file (inline CSS, no assets, no network)
an operator can hand to a client or open in a browser. Same state, same ordering, a
severity-coloured executive summary up top.

Deterministic string building; every dynamic value passes through `_esc` so a banner
or secret containing ``<`` can't break out of the markup.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from html import escape

from ..core.state import EngagementState, Finding, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]
_SEV_COLOR = {
    Severity.CRITICAL: "#b0003a", Severity.HIGH: "#d9480f", Severity.MEDIUM: "#e8a800",
    Severity.LOW: "#2b8a3e", Severity.INFO: "#495057",
}

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0; padding: 0 1.2rem 3rem; line-height: 1.55; color: #1a1a1a;
  background: #fafafa; max-width: 60rem; margin-inline: auto; }
h1 { margin: 1.4rem 0 .2rem; font-size: 1.7rem; }
h2 { margin: 2.2rem 0 .6rem; padding-bottom: .3rem; border-bottom: 2px solid #e3e3e3;
  font-size: 1.25rem; }
h3 { margin: 1.4rem 0 .3rem; font-size: 1.05rem; }
.sub { color: #666; font-size: .9rem; }
.cards { display: flex; flex-wrap: wrap; gap: .6rem; margin: 1rem 0; }
.card { flex: 1 1 7rem; background: #fff; border: 1px solid #e3e3e3; border-radius: 8px;
  padding: .7rem .9rem; }
.card .n { font-size: 1.5rem; font-weight: 700; }
.card .l { color: #666; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
.badge { display: inline-block; color: #fff; font-size: .72rem; font-weight: 700;
  padding: .1rem .5rem; border-radius: 4px; vertical-align: middle; letter-spacing: .03em; }
.sevbar { display: flex; height: .6rem; border-radius: 4px; overflow: hidden; margin: .4rem 0 0; }
table { border-collapse: collapse; width: 100%; margin: .6rem 0; font-size: .9rem; }
th, td { border: 1px solid #e3e3e3; padding: .35rem .5rem; text-align: left; }
th { background: #f1f3f5; }
pre { background: #1e1e28; color: #e6e6ef; padding: .7rem .9rem; border-radius: 6px;
  overflow-x: auto; font-size: .82rem; }
.finding { border: 1px solid #e3e3e3; border-left-width: 5px; border-radius: 6px;
  padding: .3rem 1rem 1rem; margin: 1rem 0; background: #fff; }
.muted { color: #666; }
@media (prefers-color-scheme: dark) {
  body { background: #14141a; color: #e6e6ef; }
  h2 { border-color: #2a2a35; } .card, .finding, th { background: #1e1e28; border-color: #2a2a35; }
  th { background: #24242f; } .sub, .muted, .card .l { color: #9a9aa8; }
}
"""


def _esc(v: object) -> str:
    return escape(str(v), quote=True)


def render_html(state: EngagementState) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    parts = [
        "<!doctype html>", "<html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>Engagement report — {_esc(state.name)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>Engagement report — {_esc(state.name)}</h1>",
        f"<p class='sub'>Generated {now} · phase reached: {_esc(state.phase.value)}</p>",
    ]
    parts += _summary(state)
    parts += _findings(state)
    parts += _hosts(state)
    parts += _credentials(state)
    parts += _timeline(state)
    parts.append("</body></html>")
    return "\n".join(parts)


def _summary(state: EngagementState) -> list[str]:
    counts = Counter(f.severity for f in state.findings)
    total = sum(counts.values())
    n_svc = sum(len(h.services) for h in state.hosts.values())
    cards = [
        ("Hosts", len(state.hosts)), ("Services", n_svc),
        ("Findings", total), ("Credentials", len(state.credentials)),
        ("Flags", len(state.flags)),
    ]
    out = ["<h2>Executive summary</h2>", "<div class='cards'>"]
    for label, n in cards:
        out.append(f"<div class='card'><div class='n'>{n}</div>"
                   f"<div class='l'>{_esc(label)}</div></div>")
    out.append("</div>")
    if total:
        out.append("<div class='sevbar'>")
        for s in _SEVERITY_ORDER:
            if counts[s]:
                pct = counts[s] / total * 100
                out.append(f"<span title='{counts[s]} {_esc(s.value)}' "
                           f"style='width:{pct:.1f}%;background:{_SEV_COLOR[s]}'></span>")
        out.append("</div>")
        badges = " ".join(
            f"<span class='badge' style='background:{_SEV_COLOR[s]}'>"
            f"{counts[s]} {_esc(s.value.upper())}</span>"
            for s in _SEVERITY_ORDER if counts[s])
        out.append(f"<p>{badges}</p>")
    return out


def _findings(state: EngagementState) -> list[str]:
    if not state.findings:
        return []
    out = ["<h2>Findings</h2>"]
    ordered = sorted(state.findings, key=lambda f: _SEVERITY_ORDER.index(f.severity))
    for f in ordered:
        out += _finding_block(f)
    return out


def _finding_block(f: Finding) -> list[str]:
    color = _SEV_COLOR.get(f.severity, "#495057")
    loc = " · ".join(x for x in (f.host, f.service_key) if x)
    out = [f"<div class='finding' style='border-left-color:{color}'>",
           f"<h3><span class='badge' style='background:{color}'>"
           f"{_esc(f.severity.value.upper())}</span> {_esc(f.title)}</h3>"]
    from .scoring import score_label
    out.append(f"<p class='muted'>CVSS: {_esc(score_label(f))}</p>")
    if loc:
        out.append(f"<p class='muted'>Location: {_esc(loc)}</p>")
    if f.cve:
        out.append(f"<p class='muted'>CVE: {_esc(', '.join(f.cve))}</p>")
    if f.description:
        out.append(f"<p>{_esc(f.description)}</p>")
    if f.exploit:
        out.append("<p><strong>Guided exploit</strong> "
                   "(review before running — confirm-gated):</p>")
        out.append(f"<pre>{_esc(f.exploit.strip())}</pre>")
    if f.remediation:
        out.append(f"<p><strong>Remediation:</strong> {_esc(f.remediation)}</p>")
    if f.evidence:
        out.append(f"<pre>{_esc(f.evidence.strip()[:1500])}</pre>")
    out.append("</div>")
    return out


def _hosts(state: EngagementState) -> list[str]:
    if not state.hosts:
        return []
    out = ["<h2>Hosts &amp; services</h2>",
           "<table><tr><th>Host</th><th>OS</th><th>Port</th>"
           "<th>Service</th><th>Version</th></tr>"]
    for host in state.hosts.values():
        os_ = _esc(host.os_guess or "?")
        if not host.services:
            out.append(f"<tr><td>{_esc(host.address)}</td><td>{os_}</td>"
                       "<td>—</td><td>—</td><td>—</td></tr>")
            continue
        for svc in sorted(host.services.values(), key=lambda s: s.port):
            product = _esc(" ".join(x for x in (svc.product, svc.version) if x) or "—")
            out.append(f"<tr><td>{_esc(host.address)}</td><td>{os_}</td>"
                       f"<td>{_esc(svc.key)}</td><td>{_esc(svc.name or '?')}</td>"
                       f"<td>{product}</td></tr>")
    out.append("</table>")
    return out


def _credentials(state: EngagementState) -> list[str]:
    if not state.credentials:
        return []
    out = ["<h2>Credentials</h2>",
           "<table><tr><th>Username</th><th>Secret</th><th>Kind</th>"
           "<th>Service</th><th>Validated</th></tr>"]
    for c in state.credentials:
        out.append(f"<tr><td>{_esc(c.username or '—')}</td><td>{_esc(c.secret or '—')}</td>"
                   f"<td>{_esc(c.kind)}</td><td>{_esc(c.service_key or '—')}</td>"
                   f"<td>{'yes' if c.validated else 'no'}</td></tr>")
    out.append("</table>")
    return out


def _timeline(state: EngagementState) -> list[str]:
    if not state.history:
        return []
    out = ["<h2>Activity timeline</h2>", "<table><tr><th>Phase</th><th>Tool</th>"
           "<th>Command</th><th>Status</th></tr>"]
    for a in state.history:
        status = "blocked/skipped" if not a.approved else f"exit {a.exit_code}"
        cmd = " ".join(a.command).replace("{OUTFILE}", "output.json")
        out.append(f"<tr><td>{_esc(a.phase.value)}</td><td>{_esc(a.tool)}</td>"
                   f"<td><code>{_esc(cmd)}</code></td><td>{_esc(status)}</td></tr>")
    out.append("</table>")
    return out
