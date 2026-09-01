"""breachload CLI."""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from pathlib import Path

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape

from .analysis.analyzer import Analyzer
from .analysis.flags import find_flags
from .analysis.gtfobins import known_binaries, lookup
from .analysis.postexploit import loot as postexploit_loot
from .analysis.suggest import SuggestionEngine
from .banner import print_banner
from .core.config import EngagementConfig
from .core.environment import check_tools, check_wordlists
from .core.llm import Planner
from .core.orchestrator import Orchestrator
from .core.ratelimit import RateLimiter
from .core.state import ActionRecord, Credential, EngagementState, Phase
from .exploit.delivery import deliver_artifact, method_by_name
from .exploit.generators import GenerationError, MsfvenomGenerator, PayloadSpec
from .exploit.library import PayloadLibrary
from .exploit.poc import PocGenerator
from .report.engine import render_markdown
from .report.pdf import render_pdf
from .safety.audit import AuditLog
from .safety.scope import Scope
from .safety.validator import Validator
from .tools.registry import allowed_binaries, default_registry

app = typer.Typer(help="breachload - autonomous pentest copilot", no_args_is_help=True)
console = Console()

ENGAGEMENTS = Path("engagements")

_STYLES = {
    "run": "bold cyan", "note": "green", "blocked": "bold red",
    "skipped": "yellow", "error": "bold red", "phase": "bold magenta",
    "finding": "bold yellow",
}


@app.callback()
def _root(no_banner: bool = typer.Option(
        False, "--no-banner", help="suppress the startup banner")):
    """breachload - autonomous, safety-gated pentest copilot."""
    # Show the banner only for interactive runs, so piped/scripted output and the
    # test harness stay clean. Also suppressible via --no-banner or the env var.
    if (not no_banner and sys.stdout.isatty()
            and os.environ.get("BREACHLOAD_NO_BANNER") != "1"):
        print_banner(console)


def _emit(event: str, msg: str) -> None:
    console.print(f"[{_STYLES.get(event, 'white')}]{event:>8}[/] {msg}")


def _confirm(prompt: str) -> bool:
    console.print(f"[yellow]confirm[/] {prompt}")
    return typer.confirm("  run this?", default=False)


# Friendly short aliases for the phase enum values, so `--phase vuln` works and
# a typo yields a clear message instead of a raw ValueError traceback.
_PHASE_ALIASES = {
    "recon": Phase.RECON,
    "enum": Phase.ENUM, "enumeration": Phase.ENUM,
    "vuln": Phase.VULN, "vuln_analysis": Phase.VULN, "vuln-analysis": Phase.VULN,
}


def _parse_phase(value: str) -> Phase:
    key = value.strip().lower()
    if key in _PHASE_ALIASES:
        return _PHASE_ALIASES[key]
    try:
        return Phase(key)
    except ValueError:
        valid = ", ".join(sorted(_PHASE_ALIASES))
        console.print(f"[bold red]invalid phase:[/] {escape(value)}  (choose one of: {valid})")
        raise typer.Exit(2) from None


def _load_config(path: Path) -> EngagementConfig:
    """Load an engagement YAML, turning any load/validation error into a clean
    message + exit instead of a raw traceback (missing file, bad YAML, invalid
    field such as a typo'd auto_threshold/mode)."""
    try:
        return EngagementConfig.load(path)
    except FileNotFoundError:
        console.print(f"[bold red]config not found:[/] {escape(str(path))}")
    except yaml.YAMLError as exc:
        console.print(f"[bold red]invalid YAML in {escape(str(path))}:[/] {escape(str(exc))}")
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'config'}: {e['msg']}"
            for e in exc.errors()
        )
        console.print(f"[bold red]invalid config {escape(str(path))}:[/] {escape(problems)}")
    raise typer.Exit(2)


def _load_state(path: Path) -> EngagementState:
    """Load engagement state, turning a corrupt/invalid state.json into a clean
    message instead of a raw traceback (e.g. an interrupted pre-atomic-save file,
    or a hand-edit typo)."""
    try:
        return EngagementState.load(path)
    except (ValueError, ValidationError) as exc:
        console.print(f"[bold red]corrupt state file {escape(str(path))}:[/] {escape(str(exc))}")
        console.print("[dim]delete it to start fresh, or restore a backup.[/]")
        raise typer.Exit(2) from None


def _write_pdf(text: str, pdf_path: Path, name: str) -> None:
    # A glitch in the (hand-rolled) PDF writer must not lose the report - the
    # Markdown is already saved, so a PDF failure is a warning, not a crash.
    try:
        pdf_path.write_bytes(render_pdf(text, title=f"breachload - {name}"))
        console.print(f"[bold green]report[/] {pdf_path}")
    except Exception as exc:  # noqa: BLE001 - keep the Markdown report
        console.print(f"[yellow]PDF generation failed ({exc}); Markdown report is saved.[/]")


def _resolves(target: str) -> bool:
    """True for an IP literal or a name that currently resolves (DNS or /etc/hosts)."""
    try:
        socket.getaddrinfo(target, None)
        return True
    except socket.gaierror:
        return False


def _load_or_seed_state(cfg: EngagementConfig, state_path: Path) -> EngagementState:
    """Resume an existing engagement, or start a fresh state seeded from targets."""
    if state_path.exists():
        return _load_state(state_path)
    state = EngagementState(name=cfg.name)
    unresolved: list[str] = []
    for target in cfg.targets:
        if any(c in target for c in "/*"):   # CIDR/glob -> scope, not a host record
            continue
        if _resolves(target):
            state.upsert_host(target)
        else:
            # A vhost like `app.box.htb` may not resolve yet; seeding it would make
            # recon waste a scan and leave a dead "no services" host. Keep it in
            # scope (it can be discovered later via a redirect + /etc/hosts) but
            # don't scan it now.
            unresolved.append(target)
    if unresolved:
        console.print(f"[yellow]not seeding unresolved target(s):[/] {', '.join(unresolved)} "
                      "- add them to /etc/hosts to enumerate, or they'll be picked up "
                      "if a redirect reveals them.")
    return state


def _warn_if_no_hosts(state: EngagementState, cfg: EngagementConfig) -> None:
    """A CIDR/glob-only scope seeds no hosts, and there's no auto host-discovery
    yet - so the engagement would silently do nothing. Say so, loudly."""
    if state.hosts:
        return
    net = [t for t in cfg.targets if any(c in t for c in "/*")]
    if net:
        console.print(f"[bold yellow]no hosts to scan:[/] scope has network/glob targets "
                      f"({', '.join(net)}) but no explicit host. breachload does not "
                      "auto-discover hosts yet - add specific target IP(s) to the config.")
    else:
        console.print("[bold yellow]no hosts to scan[/] - check the engagement targets.")


@app.command(rich_help_panel="Setup & control")
def init(name: str = typer.Option(None, help="engagement name"),
         targets: str = typer.Option(None, help="comma-separated targets (IPs/CIDRs/domains)"),
         lhost: str = typer.Option(None, help="your listener IP (attacker box)"),
         lport: int = typer.Option(4444, help="listener port"),
         mode: str = typer.Option("full-auto", help="advisor | semi-auto | full-auto"),
         ctf: bool = typer.Option(True, "--ctf/--no-ctf", help="CTF defaults (aggressive)"),
         output: Path = typer.Option(None, help="where to write the YAML "
                                     "(default: engagements/<name>.yaml)")):
    """Create an engagement YAML interactively - no hand-editing needed.

    Prompts for anything you don't pass as an option. A good first command.
    """
    interactive = sys.stdout.isatty()
    if not name:
        name = typer.prompt("Engagement name", default="lab") if interactive else "lab"
    if not targets:
        targets = (typer.prompt("Target(s) - IP/CIDR/domain, comma-separated")
                   if interactive else "")
    target_list = [t.strip() for t in (targets or "").split(",") if t.strip()]
    if lhost is None:
        lhost = (typer.prompt("Your listener IP (LHOST), blank to skip", default="")
                 if interactive else "")

    # First-run authorization checklist - a deliberate speed bump.
    if interactive:
        console.print("\n[bold yellow]Authorization check[/] - scanning a host you do not have "
                      "written permission to test is illegal.")
        if not typer.confirm("  Do you have authorization for the target(s) above?",
                             default=False):
            console.print("[yellow]aborted - get written authorization first[/]")
            raise typer.Exit(1)

    cfg = {"name": name, "targets": target_list, "mode": mode, "ctf": ctf}
    if lhost:
        cfg["lhost"] = lhost
        cfg["lport"] = lport
    out = output or (ENGAGEMENTS / f"{name}.yaml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    console.print(f"\n[bold green]created[/] {out}")
    console.print("[dim]next:[/]")
    console.print("  breachload doctor            # check your tools", markup=False)
    console.print(f"  breachload auto {out}        # recon -> plan -> report", markup=False)


@app.command(rich_help_panel="Setup & control")
def run(config: Path = typer.Argument(..., help="engagement YAML"),
        phase: str = typer.Option(None, help="run only this phase (recon/enumeration/vuln)"),
        stop: str = typer.Option("vuln_analysis", help="auto-chain stops after this phase"),
        dry_run: bool = typer.Option(False, "--dry-run",
                                     help="preview the commands without running them")):
    """Run an engagement. By default auto-chains recon -> enumeration -> vuln."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_or_seed_state(cfg, state_path)
    _warn_if_no_hosts(state, cfg)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    planner = Planner(config=cfg)
    audit = AuditLog(work / "audit.jsonl")

    planner_mode = "online (Claude)" if planner.online else "offline (heuristic)"
    label = f"phase={phase}" if phase else f"auto -> {stop}"
    dry = " | [bold]DRY-RUN[/]" if dry_run else ""
    console.print(f"[bold]breachload[/] - {cfg.name} | {label} | "
                  f"mode={cfg.mode} | planner={planner_mode}{dry}")
    console.print(state.summary())
    console.print()

    orch = Orchestrator(cfg, state, registry, validator, planner, audit,
                        state_path, confirm=_confirm, on_event=_emit,
                        analyzer=Analyzer.default(), dry_run=dry_run)
    if phase:
        state.phase = _parse_phase(phase)
        asyncio.run(orch.run_phase())
    else:
        asyncio.run(orch.run_engagement(stop_after=_parse_phase(stop)))

    state.save(state_path)
    console.print()
    console.print(state.summary())


@app.command(rich_help_panel="Setup & control")
def auto(config: Path = typer.Argument(..., help="engagement YAML"),
         lhost: str = typer.Option(None, help="your listener host for the attack plan "
                                   "(defaults to the engagement's lhost)"),
         lport: int = typer.Option(None, help="listener port for the attack plan"),
         stop: str = typer.Option("vuln_analysis", help="auto-chain stops after this phase"),
         pdf: bool = typer.Option(True, "--pdf/--no-pdf", help="also write a PDF report")):
    """Autopilot: recon -> enum -> vuln, then print an attack plan and write a report.

    One command, no API key needed. Safe recon/enumeration/vuln scanning runs
    automatically (anything above the threshold still asks); then the rule-based
    engine prints exactly what to try next, and a report is written.
    """
    cfg = _load_config(config)
    lhost = lhost or cfg.lhost or "LHOST"
    lport = lport or cfg.lport
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_or_seed_state(cfg, state_path)
    _warn_if_no_hosts(state, cfg)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    planner = Planner(config=cfg)
    audit = AuditLog(work / "audit.jsonl")
    rate = RateLimiter(cfg.min_action_interval) if cfg.min_action_interval > 0 else None

    console.print(f"[bold]breachload autopilot[/] - {cfg.name} | auto -> {stop} | "
                  f"planner={'Claude' if planner.online else 'heuristic'}\n")

    orch = Orchestrator(cfg, state, registry, validator, planner, audit, state_path,
                        confirm=_confirm, on_event=_emit, analyzer=Analyzer.default(),
                        rate_limiter=rate)
    asyncio.run(orch.run_engagement(stop_after=_parse_phase(stop)))
    state.save(state_path)

    console.print("\n" + state.summary() + "\n")

    suggestions = SuggestionEngine().suggest(state, lhost=lhost, lport=lport)
    if suggestions:
        console.print("[bold]== attack plan (suggested next steps) ==[/]\n")
        for s in suggestions:
            console.print(f"[bold cyan]> {escape(s.title)}[/]  [dim]{escape(s.why)}[/]")
            for action in s.actions:
                console.print("    " + action, markup=False)
            console.print()

    md = render_markdown(state)
    report_path = work / "report.md"
    report_path.write_text(md, encoding="utf-8")
    console.print(f"[bold green]report[/] {report_path}")
    if pdf:
        _write_pdf(md, report_path.with_suffix(".pdf"), cfg.name)


@app.command(rich_help_panel="Exploitation")
def session(config: Path = typer.Argument(..., help="engagement YAML"),
            webshell: str = typer.Option(None, help="webshell URL with a FUZZ marker, "
                                         "e.g. 'http://host/shell.php?cmd=FUZZ'"),
            ssh: str = typer.Option(None, help="ssh foothold as 'user:pass@host[:port]'"),
            winrm: str = typer.Option(None, help="winrm foothold as 'user:pass@host[:port]'"),
            test: bool = typer.Option(False, "--test", help="run `id` through the session")):
    """Register a foothold session (webshell/ssh/winrm) that auto-exploit drives for privesc.

    The session's host must be in scope. Stored in engagements/<name>/session.json;
    auto-exploit uses it to autonomously enumerate and escalate in the POST phase.
    """
    from .core.session import Session, SshSession, WebshellSession, WinrmSession
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    sess_path = work / "session.json"

    sess: Session | None = None
    try:
        if webshell:
            sess = WebshellSession.from_spec(webshell)
        elif ssh:
            sess = SshSession.from_spec(ssh)
        elif winrm:
            sess = WinrmSession.from_spec(winrm)
    except ValueError as exc:
        console.print(f"[bold red]bad session spec:[/] {escape(str(exc))}")
        raise typer.Exit(2) from None

    if sess is not None:
        scope = Scope.from_config(cfg.targets, cfg.exclude)
        if not scope.allows(sess.host):
            console.print(f"[bold red]refused:[/] session host {escape(sess.host)} is out of scope")
            raise typer.Exit(2)
        sess.save(sess_path)
        console.print(f"[bold green]session set[/] ({sess.to_dict()['kind']}) on {sess.host}")
    else:
        sess = Session.load(sess_path)
        if sess is None:
            console.print("[yellow]no session set[/] - add one with --webshell, --ssh or --winrm")
            raise typer.Exit(1)
        console.print(f"[bold]session[/] ({sess.to_dict()['kind']}) on {sess.host}")

    if test:
        probe = "whoami" if sess.to_dict()["kind"] == "winrm" else "id"
        out = sess.run(probe)
        console.print(f"[dim]$ {probe}[/]")
        console.print(out.strip() or "[yellow](no output)[/]", markup=False)


@app.command(name="auto-exploit", rich_help_panel="Setup & control")
def auto_exploit(config: Path = typer.Argument(..., help="engagement YAML"),
                 lhost: str = typer.Option(None, help="listener host for the attack plan"),
                 lport: int = typer.Option(None, help="listener port"),
                 yes: bool = typer.Option(False, "--yes",
                                          help="skip the interactive 'are you sure' prompt")):
    """AUTHORIZED autonomous mode: auto-walk recon -> exploitation -> post-exploitation.

    Removes per-action confirmation up to EXPLOIT (DESTRUCTIVE actions still ask a
    human, and off-scope targets are always hard-blocked). Requires the engagement
    to set `auto_exploit: true` and `authorized: true`, AND the running operator to
    pass the operator gate ($BREACHLOAD_OPERATOR / $BREACHLOAD_TOKEN vs the operators
    file). Every action - and the authorization itself - is written to the audit log.
    """
    from .core.authz import gate_auto_exploit
    from .safety.validator import Risk

    cfg = _load_config(config)
    decision = gate_auto_exploit(cfg)
    if not decision.authorized:
        console.print(f"[bold red]auto-exploit refused:[/] {escape(decision.reason)}")
        console.print("[dim]the engine will not run autonomously without a passing gate. "
                      "Use `breachload auto` for the safe, confirm-gated walk.[/]")
        raise typer.Exit(2)

    lhost = lhost or cfg.lhost or "LHOST"
    lport = lport or cfg.lport
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_or_seed_state(cfg, state_path)
    _warn_if_no_hosts(state, cfg)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    console.print("[bold red]== AUTO-EXPLOIT MODE ==[/]")
    console.print(f"  operator : [bold]{escape(decision.operator or '?')}[/]")
    console.print(f"  scope    : {', '.join(cfg.targets) or '(none)'}")
    console.print("  bounds   : auto up to EXPLOIT; DESTRUCTIVE still asks; off-scope "
                  "hard-blocked; all audited.")
    if not yes and sys.stdout.isatty() and not typer.confirm(
            "  proceed with autonomous exploitation of the scope above?", default=False):
        console.print("[yellow]aborted[/]")
        raise typer.Exit(0)

    registry = default_registry()
    # Threshold raised to EXPLOIT: exploit-class actions run without asking, but the
    # scope check is unchanged (off-scope is always denied) and DESTRUCTIVE (> EXPLOIT)
    # still routes to confirm() - a human.
    validator = Validator(scope, allowed_binaries(registry), Risk.EXPLOIT)
    planner = Planner(config=cfg)
    audit = AuditLog(work / "audit.jsonl")
    audit.write("authorization", mode="auto-exploit", operator=decision.operator,
                scope=cfg.targets, engagement=cfg.name)
    rate = RateLimiter(cfg.min_action_interval) if cfg.min_action_interval > 0 else None

    # A registered foothold session enables autonomous POST-phase privesc.
    from .core.session import Session
    sess = Session.load(work / "session.json")
    if sess is not None:
        console.print(f"  session  : autonomous privesc via {sess.to_dict()['kind']} "
                      f"on {sess.host}")

    orch = Orchestrator(cfg, state, registry, validator, planner, audit, state_path,
                        confirm=_confirm, on_event=_emit, analyzer=Analyzer.default(),
                        rate_limiter=rate, auto_exploit=True, session=sess)
    asyncio.run(orch.run_engagement(stop_after=Phase.POST))
    state.save(state_path)
    # Persist a session the engine auto-established, so it can be reused/inspected.
    if orch.session is not None and sess is None:
        orch.session.save(work / "session.json")
        console.print(f"[bold green]session[/] auto-established on {orch.session.host}")

    console.print("\n" + state.summary() + "\n")
    suggestions = SuggestionEngine().suggest(state, lhost=lhost, lport=lport)
    if suggestions:
        console.print("[bold]== attack plan (remaining manual / guided steps) ==[/]\n")
        for s in suggestions:
            console.print(f"[bold cyan]> {escape(s.title)}[/]  [dim]{escape(s.why)}[/]")
            for action in s.actions:
                console.print("    " + action, markup=False)
            console.print()

    md = render_markdown(state)
    report_path = work / "report.md"
    report_path.write_text(md, encoding="utf-8")
    console.print(f"[bold green]report[/] {report_path}")


@app.command(rich_help_panel="Setup & control")
def serve(config: Path = typer.Argument(..., help="engagement YAML"),
          host: str = typer.Option("127.0.0.1", help="bind host"),
          port: int = typer.Option(8000, help="bind port"),
          phase: str = typer.Option(None, help="run only this phase"),
          stop: str = typer.Option("vuln_analysis", help="auto-chain stops after this phase")):
    """Run an engagement with a live web dashboard (follow + approve in the browser)."""
    try:
        import uvicorn

        from .web.hub import EventHub
        from .web.server import create_app
    except ImportError:
        console.print("[bold red]web extra not installed[/] - run: pip install 'breachload[web]'")
        raise typer.Exit(1) from None

    cfg = _load_config(config)
    # Resolve phases up front so a bad value errors clearly before the server boots.
    target_phase = _parse_phase(phase) if phase else None
    stop_phase = _parse_phase(stop)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_or_seed_state(cfg, state_path)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    audit = AuditLog(work / "audit.jsonl")
    hub = EventHub()
    rate = RateLimiter(cfg.min_action_interval) if cfg.min_action_interval > 0 else None
    orch = Orchestrator(cfg, state, registry, validator, Planner(config=cfg), audit, state_path,
                        # Orchestrator.confirm is async-capable at runtime via
                        # inspect.isawaitable - the type stub of confirm is sync,
                        # so we suppress the annotation-only mismatch here.
                        confirm=hub.request_confirm,  # type: ignore[arg-type]
                        on_event=hub.emit,
                        analyzer=Analyzer.default(), rate_limiter=rate,
                        on_state=lambda st: hub.emit_state(st.dashboard_payload()))
    hub.emit_state(state.dashboard_payload())   # seed the initial snapshot

    async def _boot():
        async def _run():
            # A crash in the background engagement must surface on the dashboard
            # (not vanish into an unretrieved task) and the state must still save.
            try:
                if phase:
                    state.phase = target_phase
                    await orch.run_phase()
                else:
                    await orch.run_engagement(stop_after=stop_phase)
                hub.emit("phase", "== engagement finished ==")
            except Exception as exc:  # noqa: BLE001 - report, don't swallow
                hub.emit("error", f"engagement crashed: {exc}")
            finally:
                state.save(state_path)
        asyncio.create_task(_run())

    def _stop() -> None:
        orch.request_stop()
        hub.cancel_pending()   # unblock any confirm the engine is waiting on

    web_app = create_app(hub, state_path, on_startup=_boot, stopper=_stop)
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[bold red]warning:[/] binding beyond localhost - the confirm/stop "
                      "endpoints are unauthenticated; anyone who can reach this port can "
                      "approve risky actions.")
    console.print(f"[bold]breachload[/] dashboard: http://{host}:{port}  (engagement: {cfg.name})")
    uvicorn.run(web_app, host=host, port=port, log_level="warning")


@app.command(rich_help_panel="Exploitation")
def payloads(category: str = typer.Option(None, help="filter by category"),
             tag: str = typer.Option(None, help="filter by tag (shell, http, smb, privesc, ...)"),
             platform: str = typer.Option(None, help="filter by platform (linux/windows)"),
             show: str = typer.Option(None, "--show", help="render a single payload by id"),
             lhost: str = typer.Option("LHOST", help="substitute for {LHOST}"),
             lport: int = typer.Option(4444, help="substitute for {LPORT}"),
             target: str = typer.Option("TARGET", help="substitute for {TARGET}")):
    """Browse the offline payload/technique library (no config, no API needed)."""
    lib = PayloadLibrary.default()
    if show:
        p = lib.get(show)
        if p is None:
            console.print(f"[bold red]no such payload:[/] {show}")
            raise typer.Exit(1)
        console.print(f"[bold]{escape(p.name)}[/]  ({p.category} / {p.platform})")
        # markup=False: payload bodies contain [ ] { } that must print verbatim.
        console.print(p.render(LHOST=lhost, LPORT=lport, TARGET=target), markup=False)
        if p.notes:
            console.print(escape(p.notes), style="dim")
        return
    entries = lib.filter(category=category, tag=tag, platform=platform)
    console.print(f"[bold]breachload payload library[/] - {len(entries)} entries "
                  f"| categories: {', '.join(lib.categories())}")
    for p in entries:
        console.print(f"  [cyan]{p.id:<18}[/] [dim]{p.category:<14}[/] {escape(p.name)}")
    console.print("\n[dim]render one with:  breachload payloads --show <id> "
                  "--lhost <ip> --lport <port>[/]")


@app.command(rich_help_panel="Recon, enum & planning")
def suggest(config: Path = typer.Argument(..., help="engagement YAML"),
            lhost: str = typer.Option(None, help="your listener host for rendered payloads "
                                      "(defaults to the engagement's lhost)"),
            lport: int = typer.Option(None, help="listener port")):
    """Rule-based next-step plan from the current state (works with no API key)."""
    cfg = _load_config(config)
    lhost = lhost or cfg.lhost or "LHOST"
    lport = lport or cfg.lport
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run a phase first[/]")
        raise typer.Exit(1)
    state = _load_state(state_path)
    suggestions = SuggestionEngine().suggest(state, lhost=lhost, lport=lport)
    if not suggestions:
        console.print("[yellow]nothing to suggest yet - run more recon[/]")
        return
    console.print(f"[bold]breachload - suggested next steps[/] ({len(suggestions)})\n")
    for s in suggestions:
        console.print(f"[bold cyan]> {escape(s.title)}[/]  [dim]{escape(s.why)}[/]")
        for action in s.actions:
            console.print("    " + action, markup=False)   # actions contain [ ] { } # verbatim
        console.print()


@app.command(name="kb-import", rich_help_panel="Learn & knowledge base")
def kb_import(nvd: Path = typer.Argument(..., help="NVD 2.0 JSON feed"),
              output: Path = typer.Option("breachload_kb.json", help="KB file to write")):
    """Convert an NVD 2.0 feed into a breachload KB file (grow the CVE knowledge base).

    Point BREACHLOAD_KB at the output file to have the analyzer use these CVEs:
      export BREACHLOAD_KB=$(pwd)/breachload_kb.json
    """
    import json as _json

    from .analysis.nvd import parse_nvd
    data = _json.loads(Path(nvd).read_text(encoding="utf-8"))
    entries = parse_nvd(data)
    Path(output).write_text(_json.dumps({"entries": entries}, indent=2), encoding="utf-8")
    console.print(f"[bold green]imported[/] {len(entries)} usable CVE entries -> {output}")
    console.print(f"[dim]use them:  export BREACHLOAD_KB={Path(output).resolve()}[/]")


# Install hints for the external tools, shown by `doctor --install` for the ones
# that are missing. Kali/Debian apt names, with pipx/go for the rest.
_INSTALL_HINTS = {
    "nmap": "sudo apt install -y nmap",
    "whatweb": "sudo apt install -y whatweb",
    "ffuf": "sudo apt install -y ffuf",
    "gobuster": "sudo apt install -y gobuster",
    "enum4linux-ng": "pipx install enum4linux-ng",
    "smbclient": "sudo apt install -y smbclient",
    "snmpwalk": "sudo apt install -y snmp",
    "showmount": "sudo apt install -y nfs-common",
    "redis-cli": "sudo apt install -y redis-tools",
    "smtp-user-enum": "sudo apt install -y smtp-user-enum",
    "curl": "sudo apt install -y curl",
    "ldapsearch": "sudo apt install -y ldap-utils",
    "rpcinfo": "sudo apt install -y rpcbind",
    "rsync": "sudo apt install -y rsync",
    "mysql": "sudo apt install -y default-mysql-client",
    "psql": "sudo apt install -y postgresql-client",
    "mongosh": "https://www.mongodb.com/docs/mongodb-shell/install/",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "searchsploit": "sudo apt install -y exploitdb",
    "msfvenom": "sudo apt install -y metasploit-framework",
    "msfconsole": "sudo apt install -y metasploit-framework",
    "hydra": "sudo apt install -y hydra",
    "nxc": "pipx install netexec",
    "netexec": "pipx install netexec",
    "bloodhound-python": "pipx install bloodhound",
    "certipy": "pipx install certipy-ad",
    "bloodyAD": "pipx install bloodyAD",
    "evil-winrm": "gem install evil-winrm",
    "kerbrute": "go install github.com/ropnop/kerbrute@latest",
    "impacket-secretsdump": "pipx install impacket",
    "nc": "sudo apt install -y netcat-traditional",
    "ncat": "sudo apt install -y ncat",
    "socat": "sudo apt install -y socat",
    "python3": "sudo apt install -y python3",
    "wget": "sudo apt install -y wget",
}


@app.command(rich_help_panel="Setup & control")
def doctor(target: str = typer.Option(None, help="probe this host for the VPN "
                                      "MTU / large-response stall (needs it reachable)"),
           port: int = typer.Option(80, help="port to probe with --target"),
           install: bool = typer.Option(False, "--install",
                                        help="print an install command for each missing tool"),
           self_test: bool = typer.Option(False, "--self-test",
                                          help="run every adapter's build_command "
                                          "against the Validator (offline invariant check)")):
    """Check which external tools and wordlists are available on this machine.

    With --target, also probe the path for the MTU / large-response stall that
    makes web fingerprinting silently return nothing over a mis-MTU'd VPN.
    With --install, print the command to install each missing tool.
    With --self-test, run every registered adapter's default build_command through
    the Validator to catch a broken adapter contract without touching a target.
    """
    if self_test:
        from .safety.scope import Scope
        from .safety.validator import Risk, Validator
        from .tools.registry import allowed_binaries, default_registry
        reg = default_registry()
        scope = Scope.from_config(["10.10.10.0/24"])
        validator = Validator(scope, allowed_binaries(reg), Risk.EXPLOIT)
        console.print(f"[bold]self-test[/] {len(reg)} registered adapter(s)\n")
        failures = 0
        for adapter in reg.values():
            try:
                cmd = adapter.build_command("10.10.10.5")
                decision = validator.check(cmd, adapter.risk)
                if decision.allowed:
                    console.print(f"  [green]+[/] {adapter.name:<14} "
                                  f"[dim]{adapter.risk.name}[/]")
                else:
                    failures += 1
                    console.print(f"  [red]-[/] {adapter.name:<14} "
                                  f"[red]REFUSED[/] [dim]({escape(decision.reason)})[/]")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                console.print(f"  [red]!] {adapter.name:<14} "
                              f"[red]CRASHED[/] [dim]({escape(type(exc).__name__)}: "
                              f"{escape(str(exc))[:80]})[/]", markup=False)
        if failures:
            console.print(f"\n[bold red]{failures} adapter(s) failed the self-test[/]")
            raise typer.Exit(1)
        console.print("\n[bold green]all adapters pass the self-test[/]")
        return

    if target:
        from .core.netprobe import probe_path_mtu
        console.print(f"[bold]MTU / large-response probe[/] -> {target}:{port}\n")
        res = probe_path_mtu(target, port=port)
        if not res.ran:
            console.print(f"[yellow]{res.verdict}[/]")
        else:
            small = "[green]ok[/]" if res.small_ok else "[red]stalled[/]"
            large = "[green]ok[/]" if res.large_ok else "[red]stalled[/]"
            console.print(f"  small ranged GET: {small} ({res.small_time:.2f}s)")
            console.print(f"  full GET:         {large} ({res.large_time:.2f}s)")
            style = "bold red" if res.suggestion else "green"
            console.print(f"  [{style}]{escape(res.verdict)}[/]")
            if res.suggestion:
                console.print("  fix: " + res.suggestion, markup=False)
            # When the full GET stalls, a ranged fetch still fingerprints the app.
            if res.small_ok and not res.large_ok:
                from .core.netprobe import ranged_fingerprint
                fp = ranged_fingerprint(target, port=port)
                if fp:
                    console.print("  ranged fingerprint (first 4KB):")
                    for k, v in fp.items():
                        console.print(f"    {k}: {escape(v)}")
        console.print()
        return

    console.print("[bold]breachload environment check[/]\n")
    tools = check_tools()
    present = sum(t.present for t in tools)
    by_role: dict[str, list] = {}
    for t in tools:
        by_role.setdefault(t.role, []).append(t)
    for role, items in by_role.items():
        line = "  ".join(
            (f"[green]+[/] {t.name}" if t.present else f"[red]-[/] [dim]{t.name}[/]") for t in items
        )
        console.print(f"[bold]{role:<12}[/] {line}")
    console.print("\n[bold]wordlists[/]")
    for path, ok in check_wordlists():
        console.print(f"  {'[green]+[/]' if ok else '[red]-[/]'} {path}")
    console.print(f"\n{present}/{len(tools)} tools available. Missing tools are "
                  "skipped gracefully; suggestions still list them.")

    if install:
        missing = [t for t in tools if not t.present]
        if not missing:
            console.print("\n[green]all known tools are installed[/]")
            return
        console.print("\n[bold]install the missing tools:[/]")
        seen: set[str] = set()
        for t in missing:
            hint = _INSTALL_HINTS.get(t.name)
            if hint and hint not in seen:
                seen.add(hint)
                console.print(f"  [dim]# {t.name}[/]")
                console.print("  " + hint, markup=False)


@app.command(rich_help_panel="Learn & knowledge base")
def explain(term: str = typer.Argument(None, help="term to explain (ssti, kerberoast, esc1, ...)")):
    """Plain-language explanation of a pentest term (offline glossary for learners)."""
    from .analysis.glossary import all_terms, lookup
    if not term:
        console.print("[bold]breachload glossary[/] - explain any of:\n")
        for t in all_terms():
            console.print(f"  [cyan]{t.key:<20}[/] {escape(t.title)}")
        console.print("\n[dim]breachload explain <term>[/]")
        return
    entry = lookup(term)
    if entry is None:
        console.print(f"[yellow]no glossary entry for[/] {escape(term)}")
        console.print("[dim]run `breachload explain` to list known terms[/]")
        raise typer.Exit(1)
    console.print(f"[bold cyan]{escape(entry.title)}[/]\n")
    console.print(f"[bold]What it is:[/]  {escape(entry.what)}")
    console.print(f"[bold]Why it matters:[/]  {escape(entry.why)}")
    console.print(f"[bold]In breachload:[/]  {escape(entry.breachload)}")
    if entry.learn:
        console.print(f"[dim]Learn more: {escape(entry.learn)}[/]")


@app.command(rich_help_panel="Learn & knowledge base")
def gtfo(binary: str = typer.Argument(..., help="binary found as SUID or via `sudo -l`")):
    """Offline GTFOBins privilege-escalation lookup (find, vim, python3, tar, ...)."""
    entry = lookup(binary)
    if not entry:
        console.print(f"[yellow]no GTFOBins entry for[/] {binary}")
        console.print(f"[dim]known: {', '.join(known_binaries())}[/]")
        raise typer.Exit(1)
    console.print(f"[bold]{binary}[/] - privilege escalation\n")
    for vector, cmd in entry.items():
        console.print(f"[cyan]{vector}[/]")
        console.print("  " + cmd.replace("\n", "\n  "), markup=False)
        console.print()


@app.command(rich_help_panel="Exploitation")
def flag(config: Path = typer.Argument(..., help="engagement YAML"),
         scan: Path = typer.Option(None, help="file to scan for flags (e.g. loot/user.txt)"),
         text: str = typer.Option(None, help="text to scan for flags")):
    """Record CTF flags found in a file or text (e.g. paste your user.txt / root.txt)."""
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = (_load_state(state_path) if state_path.exists()
             else EngagementState(name=cfg.name))

    blob = ""
    if scan and Path(scan).is_file():
        blob += Path(scan).read_text(encoding="utf-8", errors="replace")
    if text:
        blob += "\n" + text
    # Explicit flag scan of a trusted file/paste: also accept bare 32-hex HTB flags.
    new = [f for f in find_flags(blob, include_bare_hex=True) if state.add_flag(f)]
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state.save(state_path)
    if new:
        console.print(f"[bold green]captured[/] {len(new)} flag(s): {', '.join(new)}")
    else:
        console.print("[yellow]no new flags found[/]")


@app.command(rich_help_panel="Post-exploitation")
def loot(config: Path = typer.Argument(..., help="engagement YAML"),
         scan: Path = typer.Option(None, help="file to parse (linpeas / sudo -l / SUID sweep)"),
         text: str = typer.Option(None, help="text to parse")):
    """Parse post-exploitation output into findings + credentials (privesc, loot)."""
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = (_load_state(state_path) if state_path.exists()
             else EngagementState(name=cfg.name))

    blob = ""
    if scan and Path(scan).is_file():
        blob += Path(scan).read_text(encoding="utf-8", errors="replace")
    if text:
        blob += "\n" + text
    if not blob.strip():
        console.print("[yellow]nothing to parse - pass --scan <file> or --text[/]")
        raise typer.Exit(1)

    findings, creds = postexploit_loot(blob)
    existing_titles = {f.title for f in state.findings}
    existing_creds = {(c.username, c.secret, c.kind) for c in state.credentials}
    new_f = [f for f in findings if f.title not in existing_titles]
    new_c = [c for c in creds if (c.username, c.secret, c.kind) not in existing_creds]
    for f in new_f:
        state.add_finding(f)
    state.credentials.extend(new_c)
    state.save(state_path)

    console.print(f"[bold green]loot[/] +{len(new_f)} findings, +{len(new_c)} credentials")
    for f in new_f:
        console.print(f"  [{f.severity.value}] {f.title}")
    for c in new_c:
        console.print(f"  cred: {c.username or '?'} / {c.secret or '?'} ({c.kind})")


@app.command(rich_help_panel="Exploitation")
def listen(config: Path = typer.Argument(..., help="engagement YAML"),
           lhost: str = typer.Option(None, help="your box IP (default: engagement lhost)"),
           lport: int = typer.Option(None, help="listener port (default: engagement lport)"),
           serve: str = typer.Option(".", help="directory to host payloads from"),
           http_port: int = typer.Option(8000, help="port for the payload web server"),
           payload: str = typer.Option("shell.sh", help="payload filename to reference"),
           run: bool = typer.Option(False, "--run",
                                    help="launch 'nc -lvnp <port>' (blocks until a shell lands)")):
    """Print a reverse-shell catch kit (listener, payload host, target one-liners, PTY upgrade)."""
    from .analysis.handler import kit_lines
    cfg = _load_config(config)
    lhost = lhost or cfg.lhost or "LHOST"
    lport = lport or cfg.lport
    console.print(f"[bold]breachload - reverse-shell handler[/]  "
                  f"[dim](LHOST={lhost} LPORT={lport})[/]\n")
    for line in kit_lines(lhost, lport, http_port, serve, payload):
        if line.startswith("#"):
            console.print(f"[bold cyan]{escape(line)}[/]")
        else:
            console.print(line, markup=False)   # commands contain [ ] { } | -> verbatim

    if run:
        import subprocess
        console.print(f"\n[bold]launching[/] nc -lvnp {lport}  (Ctrl-C to stop)\n")
        try:
            subprocess.run(["nc", "-lvnp", str(lport)])   # noqa: S603,S607 - user's own listener
        except FileNotFoundError:
            console.print("[bold red]nc not found[/] - install netcat or use one of the "
                          "listeners above")
            raise typer.Exit(1) from None
        except KeyboardInterrupt:
            console.print("\n[yellow]listener stopped[/]")


@app.command(rich_help_panel="Exploitation")
def sploit(config: Path = typer.Argument(..., help="engagement YAML")):
    """Search Exploit-DB (searchsploit) for every versioned service and record matches."""
    from .analysis.searchsploit import run_search
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run recon first[/]")
        raise typer.Exit(1)
    state = _load_state(state_path)

    from .core.environment import is_available
    if not is_available("searchsploit"):
        console.print("[yellow]searchsploit not installed[/] - "
                      "install exploitdb, then re-run")
        raise typer.Exit(1)

    findings = run_search(state)
    existing = {f.title for f in state.findings}
    new = [f for f in findings if f.title not in existing]
    for f in new:
        state.add_finding(f)
    state.save(state_path)
    console.print(f"[bold green]sploit[/] +{len(new)} Exploit-DB finding(s)")
    for f in new:
        console.print(f"  [{f.severity.value}] {escape(f.title)}")


@app.command(rich_help_panel="Active Directory")
def bloodhound(config: Path = typer.Argument(..., help="engagement YAML"),
               scan: list[Path] = typer.Option(None, help="BloodHound JSON file(s) to parse")):
    """Parse BloodHound JSON into AD attack findings (kerberoast, AS-REP, ACL edges)."""
    import json as _json

    from .analysis.bloodhound import parse_bloodhound
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = _load_state(state_path) if state_path.exists() else EngagementState(name=cfg.name)

    files = [p for p in (scan or []) if Path(p).is_file()]
    if not files:
        console.print("[yellow]pass one or more --scan <bloodhound.json> files[/]")
        raise typer.Exit(1)

    findings = []
    for fp in files:
        try:
            findings += parse_bloodhound(_json.loads(Path(fp).read_text(encoding="utf-8")))
        except (ValueError, OSError) as exc:
            console.print(f"[yellow]skip {escape(str(fp))}: {escape(str(exc))}[/]")

    existing = {f.title for f in state.findings}
    new = [f for f in findings if f.title not in existing]
    for f in new:
        state.add_finding(f)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state.save(state_path)
    console.print(f"[bold green]bloodhound[/] +{len(new)} AD finding(s)")
    for f in new[:40]:
        console.print(f"  [{f.severity.value}] {escape(f.title)}")


@app.command(rich_help_panel="Active Directory")
def adcs(config: Path = typer.Argument(..., help="engagement YAML"),
         scan: Path = typer.Option(None, help="certipy find output file to parse"),
         text: str = typer.Option(None, help="certipy find output as text")):
    """Parse `certipy find -vulnerable` output into ESC findings (with exploit commands)."""
    from .analysis.adcs import parse_certipy, parse_dangling_templates
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = _load_state(state_path) if state_path.exists() else EngagementState(name=cfg.name)

    blob = ""
    if scan and Path(scan).is_file():
        blob += Path(scan).read_text(encoding="utf-8", errors="replace")
    if text:
        blob += "\n" + text
    if not blob.strip():
        console.print("[yellow]nothing to parse - pass --scan <file> or --text[/]")
        raise typer.Exit(1)

    findings = parse_certipy(blob) + parse_dangling_templates(blob)
    existing = {f.title for f in state.findings}
    new = [f for f in findings if f.title not in existing]
    for f in new:
        state.add_finding(f)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state.save(state_path)
    console.print(f"[bold green]adcs[/] +{len(new)} ESC finding(s)")
    for f in new:
        console.print(f"  [{f.severity.value}] {f.title}")
        if f.exploit:
            console.print("    " + f.exploit, markup=False)


@app.command(rich_help_panel="Post-exploitation")
def pivot(config: Path = typer.Argument(..., help="engagement YAML"),
         via: str = typer.Option(..., "--via", help="the compromised edge host to pivot through"),
         subnet: str = typer.Option(None, help="internal subnet to reach (e.g. 172.16.5.0/24)"),
         ssh_user: str = typer.Option(None, "--ssh-user", help="SSH user on the edge host"),
         lhost: str = typer.Option(None, help="attacker host (defaults to engagement lhost)")):
    """Generate tunnelling commands (sshuttle/chisel/ligolo/ssh-fwd) to reach an internal subnet."""
    from .analysis.pivot import pivot_plan, render_pivot
    cfg = _load_config(config)
    lhost = lhost or cfg.lhost or "LHOST"
    opts = pivot_plan(lhost, via_host=via, subnet=subnet, ssh_user=ssh_user)
    console.print(f"[bold green]pivot[/] {len(opts)} option(s) via {via} "
                  f"-> {subnet or 'internal side'}\n")
    for line in render_pivot(opts):
        console.print("  " + line, markup=False)


@app.command(rich_help_panel="Active Directory")
def adchain(config: Path = typer.Argument(..., help="engagement YAML")):
    """Compose the AD findings (BloodHound/ADCS/roasting) into an ordered path to DA."""
    from .analysis.adchain import plan_ad_chain, render_chain
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run recon / bloodhound / adcs first[/]")
        raise typer.Exit(1)
    state = _load_state(state_path)
    have_creds = any(c.validated for c in state.credentials) or bool(state.credentials)
    chain = plan_ad_chain(list(state.findings), have_creds=have_creds)
    ordered = chain.ordered()
    console.print(f"[bold green]adchain[/] {len(ordered)} step(s) "
                  f"(creds held: {have_creds})")
    for line in render_chain(chain, have_creds=have_creds):
        console.print("  " + line, markup=False)


@app.command(rich_help_panel="Active Directory")
def creds(config: Path = typer.Argument(..., help="engagement YAML"),
          add: str = typer.Option(None, help="add a credential as 'user:secret' (or just 'user')"),
          kind: str = typer.Option("password", help="password | hash | key | ticket"),
          service: str = typer.Option(None, help="service key it belongs to (host:port/proto)"),
          validated: bool = typer.Option(False, "--validated", help="mark it validated")):
    """List or add credentials. Added creds auto-fill the AD / lateral / pivot chains."""
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = _load_state(state_path) if state_path.exists() else EngagementState(name=cfg.name)

    if add:
        username, sep, secret = add.partition(":")
        cred = Credential(username=username or None, secret=secret if sep else None,
                          kind=kind, service_key=service, validated=validated, source="manual")
        state.credentials.append(cred)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state.save(state_path)
        console.print(f"[bold green]added[/] {username or '?'} / {secret or '?'} ({kind})")

    if not state.credentials:
        console.print("[yellow]no credentials yet[/]")
        return
    console.print(f"[bold]credentials ({len(state.credentials)})[/]")
    for c in state.credentials:
        mark = "[green]validated[/]" if c.validated else "[dim]unvalidated[/]"
        console.print(f"  {c.username or '?'} / {c.secret or '?'} "
                      f"[dim]{c.kind}[/] {mark} [dim]{c.source or ''}[/]")


def _is_ip_literal(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@app.command(rich_help_panel="Recon, enum & planning")
def hosts(config: Path = typer.Argument(..., help="engagement YAML"),
          ip: str = typer.Option(None, help="target IP to map the vhosts to "
                                  "(default: the first IP in scope/state)"),
          write: bool = typer.Option(False, "--write",
                                     help="append the entries to /etc/hosts (privileged)")):
    """Show (and optionally add) /etc/hosts entries for discovered virtual hosts.

    Vhost/redirect discovery is inert until the name resolves. This surfaces the
    exact lines; --write appends the missing ones to /etc/hosts (a privileged,
    confirm-gated change - run with sudo).
    """
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run recon/enum first[/]")
        raise typer.Exit(1)
    state = _load_state(state_path)

    target_ip = ip or next((t for t in cfg.targets if _is_ip_literal(t)), None) \
        or next((a for a in state.hosts if _is_ip_literal(a)), None)
    if not target_ip:
        console.print("[yellow]no target IP known[/] - pass --ip <target>")
        raise typer.Exit(1)

    # Every non-IP hostname breachload has recorded (vhosts from redirects/fuzzing).
    names: list[str] = []
    for addr, host in state.hosts.items():
        for name in [addr, *host.hostnames]:
            if name and not _is_ip_literal(name) and name not in names:
                names.append(name)
    if not names:
        console.print("[yellow]no virtual hosts discovered yet[/]")
        return

    entries = [(target_ip, n) for n in names]
    console.print(f"[bold]/etc/hosts entries[/] ({len(entries)}):\n")
    for tip, n in entries:
        console.print(f"  {tip}\t{n}", markup=False)

    if not write:
        console.print("\n[dim]add them with sudo:  breachload hosts <cfg> --write[/]")
        return

    hosts_path = Path("/etc/hosts")
    try:
        existing = hosts_path.read_text(encoding="utf-8") if hosts_path.exists() else ""
    except OSError as exc:
        console.print(f"[bold red]cannot read /etc/hosts:[/] {escape(str(exc))}")
        raise typer.Exit(1) from None
    missing = [(tip, n) for tip, n in entries if n not in existing.split()]
    if not missing:
        console.print("\n[green]all entries already present in /etc/hosts[/]")
        return
    if not _confirm(f"append {len(missing)} entry(ies) to /etc/hosts"):
        console.print("[yellow]declined[/]")
        raise typer.Exit(0)
    block = "\n".join(f"{tip}\t{n}" for tip, n in missing)
    try:
        with hosts_path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n# breachload: {cfg.name}\n{block}\n")
    except OSError as exc:
        console.print(f"[bold red]cannot write /etc/hosts:[/] {escape(str(exc))} "
                      "(run with sudo)")
        raise typer.Exit(1) from None
    console.print(f"[bold green]added[/] {len(missing)} entry(ies) to /etc/hosts")


@app.command(rich_help_panel="Post-exploitation")
def privesc(config: Path = typer.Argument(..., help="engagement YAML"),
            lhost: str = typer.Option(None, help="your box IP for the transfer commands "
                                      "(defaults to the engagement's lhost)"),
            http_port: int = typer.Option(8000, help="port for your linpeas/pspy web server")):
    """Print the Linux privilege-escalation enumeration playbook (transfer + run + loot).

    Copy-paste-ready commands to stabilize a shell, triage, transfer and run
    linpeas/pspy from your box, and feed the output back to `breachload loot` -
    which names the escalation (SUID/sudo via GTFOBins, kernel via the suggester).
    """
    from .analysis.privesc_enum import playbook_lines as _pb
    cfg = _load_config(config)
    lhost = lhost or cfg.lhost or "LHOST"
    console.print(f"[bold]breachload - privilege-escalation enumeration[/]  "
                  f"[dim](LHOST={lhost})[/]\n")
    for line in _pb(lhost, http_port):
        if line and not line.startswith(" "):
            console.print(f"[bold cyan]{escape(line)}[/]")
        else:
            console.print(line, markup=False)   # commands contain [ ] { } | -> verbatim


@app.command(rich_help_panel="Post-exploitation")
def winprivesc(config: Path = typer.Argument(..., help="engagement YAML"),
               lhost: str = typer.Option(None, help="your box IP for the transfer commands"),
               http_port: int = typer.Option(8000, help="port for your winPEAS web server"),
               scan: Path = typer.Option(None, help="winPEAS/whoami output to parse into findings"),
               text: str = typer.Option(None, help="output text to parse")):
    """Windows privesc: print the winPEAS playbook, or (with --scan) parse output into findings."""
    from .analysis.winprivesc import parse_winpeas
    from .analysis.winprivesc import playbook_lines as _pb
    cfg = _load_config(config)

    blob = ""
    if scan and Path(scan).is_file():
        blob += Path(scan).read_text(encoding="utf-8", errors="replace")
    if text:
        blob += "\n" + text

    if not blob.strip():
        lhost = lhost or cfg.lhost or "LHOST"
        console.print(f"[bold]breachload - Windows privilege-escalation enum[/]  "
                      f"[dim](LHOST={lhost})[/]\n")
        for line in _pb(lhost, http_port):
            if line and not line.startswith(" "):
                console.print(f"[bold cyan]{escape(line)}[/]")
            else:
                console.print(line, markup=False)
        return

    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = _load_state(state_path) if state_path.exists() else EngagementState(name=cfg.name)
    findings = parse_winpeas(blob)
    existing = {f.title for f in state.findings}
    new = [f for f in findings if f.title not in existing]
    for f in new:
        state.add_finding(f)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state.save(state_path)
    console.print(f"[bold green]winprivesc[/] +{len(new)} finding(s)")
    for f in new:
        console.print(f"  [{f.severity.value}] {escape(f.title)}")


@app.command(rich_help_panel="Exploitation")
def crack(config: Path = typer.Argument(..., help="engagement YAML"),
          hash: str = typer.Option(None, "--hash", help="a single hash to identify/crack"),
          user: str = typer.Option(None, help="username to attach a cracked password to"),
          wordlist: str = typer.Option("/usr/share/wordlists/rockyou.txt", help="wordlist"),
          run: bool = typer.Option(False, "--run",
                                   help="actually run hashcat (else just print commands)")):
    """Identify a hash, print rockyou crack commands, and (with --run) crack + store it.

    Without --hash it processes every hash-kind credential already in state. A
    cracked plaintext is written back as a validated password credential, so the
    lateral-movement / AD suggestions can reuse it immediately.
    """
    from .analysis.hashcrack import crack_commands, identify, run_hashcat

    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    state = _load_state(state_path) if state_path.exists() else EngagementState(name=cfg.name)

    # Build the work list: an explicit --hash, else every stored hash credential.
    targets: list[tuple[str, str | None]] = []
    if hash:
        targets.append((hash, user))
    else:
        targets += [(c.secret, c.username) for c in state.credentials
                    if c.kind == "hash" and c.secret]
    if not targets:
        console.print("[yellow]no hashes to crack[/] - pass --hash or add one with "
                      "`creds --add user:<hash> --kind hash`")
        raise typer.Exit(1)

    cracked_any = False
    for raw, who in targets:
        cands = identify(raw)
        label = ", ".join(c.name for c in cands) or "unrecognized"
        console.print(f"[bold]{escape(raw[:48])}{'...' if len(raw) > 48 else ''}[/] "
                      f"[dim]-> {label}[/]")
        for cmd in crack_commands(raw, wordlist):
            console.print("    " + cmd, markup=False)
        if run:
            res = run_hashcat(raw, wordlist)
            if res.cracked and res.plaintext:
                cracked_any = True
                console.print(f"  [bold green]cracked[/] {escape(res.plaintext)} ({res.hash_type})")
                state.credentials.append(Credential(
                    username=who, secret=res.plaintext, kind="password",
                    source=f"cracked {res.hash_type}", validated=True))
            else:
                console.print(f"  [yellow]{escape(res.detail)}[/]")
        console.print()

    if cracked_any:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state.save(state_path)
        console.print("[dim]cracked passwords stored - run `suggest` to reuse them "
                      "across hosts/services.[/]")


@app.command(rich_help_panel="Active Directory")
def kerberos(config: Path = typer.Argument(..., help="engagement YAML"),
             dc: str = typer.Option(..., "--dc", help="domain controller IP"),
             domain: str = typer.Option(..., help="AD domain (e.g. corp.local)"),
             users: Path = typer.Option(None, "--users", help="username list file "
                                        "(default: usernames already in state)"),
             user: str = typer.Option(None, help="a domain user for Kerberoasting"),
             password: str = typer.Option(None, help="that user's password"),
             parse_file: Path = typer.Option(None, "--parse-file",
                                             help="parse AS-REP/TGS hashes from a file"),
             run: bool = typer.Option(False, "--run",
                                      help="actually run the AS-REP roast (impacket)")):
    """Active Kerberos: AS-REP roast + Kerberoast (print, run, or parse into state)."""
    from .analysis.kerberos import (
        asrep_command,
        creds_from_roast,
        kerberoast_command,
        parse_roast,
        userenum_command,
    )
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_state(state_path) if state_path.exists() else EngagementState(name=cfg.name)

    # Resolve the user list: an explicit file, else usernames already collected.
    userlist = str(users) if users else ""
    if not userlist:
        names = sorted({c.username for c in state.credentials if c.username})
        if names:
            work.mkdir(parents=True, exist_ok=True)
            userlist = str(work / "users.txt")
            Path(userlist).write_text("\n".join(names) + "\n", encoding="utf-8")

    console.print("[bold]Kerberos commands[/] (review before running):")
    if userlist:
        console.print("  " + " ".join(userenum_command(domain, dc, userlist)), markup=False)
        console.print("  " + " ".join(asrep_command(domain, dc, userlist)), markup=False)
    else:
        console.print("  [yellow](no user list - pass --users or collect usernames first)[/]")
    if user and password:
        console.print("  " + " ".join(kerberoast_command(domain, dc, user, password)),
                      markup=False)
    console.print()

    def _ingest(text: str) -> int:
        findings = parse_roast(text, host=dc)
        existing = {f.title for f in state.findings}
        added = 0
        for f in findings:
            if f.title not in existing:
                state.add_finding(f)
                added += 1
        for c in creds_from_roast(text):
            if not any(x.secret == c.secret for x in state.credentials):
                state.credentials.append(c)
        return added

    total = 0
    if parse_file and Path(parse_file).is_file():
        total += _ingest(Path(parse_file).read_text(encoding="utf-8", errors="replace"))
    if run and userlist:
        import subprocess
        argv = asrep_command(domain, dc, userlist)
        console.print(f"[dim]running: {' '.join(argv)}[/]")
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=180)
            total += _ingest(p.stdout + "\n" + p.stderr)
        except (OSError, subprocess.SubprocessError) as exc:
            console.print(f"[yellow]could not run impacket-GetNPUsers: {exc}[/]")

    if total:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state.save(state_path)
    console.print(f"[bold green]kerberos[/] +{total} roastable finding(s); "
                  f"run `crack` to attack the hashes.")


@app.command(rich_help_panel="Recon, enum & planning")
def unauthapi(url: str = typer.Argument(..., help="base URL to probe"),
              parse_file: Path = typer.Option(None, "--parse-file",
                                              help="parse a saved probe transcript")):
    """Probe or parse unauth admin/API endpoints (the NiFi supportsLogin:false class)."""
    from .analysis.unauth_api import classify_probes, probe_commands
    if parse_file and Path(parse_file).is_file():
        findings = classify_probes(Path(parse_file).read_text(encoding="utf-8",
                                                              errors="replace"), url)
        console.print(f"[bold green]unauth-api[/] {len(findings)} finding(s)\n")
        for f in findings:
            console.print(f"  [{f.severity.value}] {escape(f.title)}")
        return
    console.print(f"[bold]unauth-api probes[/] for {url} (review then run):")
    for c in probe_commands(url):
        console.print("  " + c, markup=False)
    console.print("\n[dim]save the transcript and re-run with --parse-file <path>[/]")


@app.command(rich_help_panel="Recon, enum & planning")
def secrets(scan: Path = typer.Option(None, "--scan", help="file to scan for secrets"),
            text: str = typer.Option(None, "--text", help="text to scan for secrets"),
            discover: str = typer.Option(None, "--discover",
                                         help="base URL: print sensitive-content probe commands")):
    """Scan text/files for secrets, or print sensitive-content discovery probes for a URL."""
    from .analysis.secretscan import content_discovery_commands, scan_secrets
    if discover:
        console.print(f"[bold]sensitive-content probes[/] for {discover}:")
        for c in content_discovery_commands(discover):
            console.print("  " + c, markup=False)
        return
    blob = ""
    if scan and Path(scan).is_file():
        blob += Path(scan).read_text(encoding="utf-8", errors="replace")
    if text:
        blob += "\n" + text
    if not blob.strip():
        console.print("[yellow]nothing to scan - pass --scan <file>, --text, "
                      "or --discover <url>[/]")
        raise typer.Exit(1)
    findings, creds = scan_secrets(blob)
    console.print(f"[bold green]secrets[/] {len(findings)} secret(s), {len(creds)} credential(s)\n")
    for f in findings:
        console.print(f"  [{f.severity.value}] {escape(f.title)}: {escape(f.evidence[:80])}")


@app.command(rich_help_panel="Recon, enum & planning")
def browser(url: str = typer.Argument(..., help="URL to render and analyse (client-side)"),
            config: Path = typer.Option(None, help="engagement YAML to record findings into")):
    """Headless-browser client-side scan: auth forms, CSRF, DOM-XSS sinks, reflected XSS.

    Renders the page with a real browser (JavaScript executed) and analyses the DOM -
    the attack surface a curl-based scan can't see. Needs the optional Playwright
    backend (`pip install playwright && playwright install chromium`).
    """
    from .analysis.browser import BrowserScan, PlaywrightDriver, available
    if not available():
        console.print("[yellow]Playwright not installed[/] - run: "
                      "pip install playwright && playwright install chromium")
        raise typer.Exit(1)
    findings = BrowserScan(PlaywrightDriver()).scan(url)
    console.print(f"[bold green]browser[/] {len(findings)} client-side finding(s) on {url}\n")
    for f in findings:
        console.print(f"  [{f.severity.value}] {escape(f.title)}")
        if f.exploit:
            console.print("    " + f.exploit, markup=False)
    if config and findings:
        cfg = _load_config(config)
        state_path = ENGAGEMENTS / cfg.name / "state.json"
        state = _load_state(state_path) if state_path.exists() else \
            EngagementState(name=cfg.name)
        existing = {fx.title for fx in state.findings}
        for f in findings:
            if f.title not in existing:
                state.add_finding(f)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state.save(state_path)
        console.print(f"[dim]recorded into {state_path}[/]")


@app.command(rich_help_panel="Setup & control")
def mcp():
    """Run breachload as an MCP server (stdio) - expose its safe tools to any LLM agent.

    Speaks JSON-RPC over stdin/stdout. Point an MCP client (Claude Code, etc.) at
    `breachload mcp`. Exposes the deterministic, non-firing surface: fingerprint->CVE,
    AD kill-chain composition, roast parsing, hash identification, pivot planning,
    the glossary, and GTFOBins - never firing a tool at a target.
    """
    from .mcp.server import serve
    serve()


@app.command(rich_help_panel="Reporting & audit")
def audit(config: Path = typer.Argument(..., help="engagement YAML"),
          verify: bool = typer.Option(True, "--verify/--no-verify",
                                      help="verify the audit hash chain")):
    """Verify the tamper-evident audit log's hash chain."""
    from .safety.audit import verify_chain
    cfg = _load_config(config)
    audit_path = ENGAGEMENTS / cfg.name / "audit.jsonl"
    if verify:
        res = verify_chain(audit_path)
        if res.records == 0:
            console.print("[yellow]no audit records yet[/]")
            return
        if res.ok:
            console.print(f"[bold green]audit chain intact[/] - {res.records} records, "
                          "no tampering detected")
        else:
            console.print(f"[bold red]audit chain BROKEN[/] at line {res.broken_at}: "
                          f"{escape(res.detail)}")
            raise typer.Exit(1)


@app.command(rich_help_panel="Setup & control")
def status(config: Path = typer.Argument(..., help="engagement YAML")):
    """Show current known state for an engagement."""
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run a phase first[/]")
        raise typer.Exit(1)
    console.print(_load_state(state_path).summary())


@app.command(rich_help_panel="Exploitation")
def payload(config: Path = typer.Argument(..., help="engagement YAML"),
            payload: str = typer.Option(..., help="msfvenom payload type"),
            lhost: str = typer.Option(..., help="your listener host (attacker IP)"),
            lport: int = typer.Option(4444, help="listener port"),
            fmt: str = typer.Option("elf", help="output format (-f): elf, exe, raw, python, ..."),
            name: str = typer.Option(None, help="artifact filename")):
    """Generate a payload artifact with msfvenom (offline - no target, no scope check)."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if state_path.exists():
        state = _load_state(state_path)
    else:
        state = EngagementState(name=cfg.name)

    spec = PayloadSpec(payload=payload, lhost=lhost, lport=lport, fmt=fmt)
    gen = MsfvenomGenerator()
    try:
        artifact, result = asyncio.run(gen.generate(spec, work / "artifacts", name))
    except GenerationError as exc:
        console.print(f"[bold red]refused[/] {exc}")
        raise typer.Exit(2) from exc

    if result.exit_code != 0:
        console.print(f"[bold red]msfvenom failed[/] (exit {result.exit_code})")
        if result.stderr:
            console.print(result.stderr.strip())
        raise typer.Exit(1)

    state.add_artifact(artifact)
    state.save(state_path)
    console.print(f"[bold green]artifact[/] {artifact.name} -> {artifact.path}")
    console.print(f"  {artifact.description}")


@app.command(rich_help_panel="Exploitation")
def poc(config: Path = typer.Argument(..., help="engagement YAML"),
        index: int = typer.Option(None, help="finding index (0-based, see report order)"),
        title: str = typer.Option(None, help="match a finding by title substring")):
    """Generate a proof-of-concept script for a finding (Claude, or offline stub)."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet[/]")
        raise typer.Exit(1)
    state = _load_state(state_path)

    finding = _select_finding(state, index, title)
    if finding is None:
        console.print("[bold red]no matching finding[/] - use --index or --title")
        raise typer.Exit(1)

    gen = PocGenerator()
    artifact = gen.generate(finding, work / "artifacts")
    state.add_artifact(artifact)
    state.save(state_path)
    src = "Claude" if gen.online else "offline template"
    console.print(f"[bold green]poc[/] {artifact.name} -> {artifact.path} ({src})")


def _select_finding(state: EngagementState, index: int | None, title: str | None):
    if index is not None and 0 <= index < len(state.findings):
        return state.findings[index]
    if title:
        return next((f for f in state.findings if title.lower() in f.title.lower()), None)
    return None


@app.command(rich_help_panel="Exploitation")
def deliver(config: Path = typer.Argument(..., help="engagement YAML"),
            artifact: str = typer.Option(..., help="artifact name (see `status`)"),
            target: str = typer.Option(..., help="target host or URL (must be in scope)"),
            method: str = typer.Option("script", help="delivery method: script | upload"),
            interpreter: str = typer.Option("python3", help="interpreter for the script method"),
            listen: bool = typer.Option(False, "--listen",
                                        help="print the matching listener command first")):
    """Deliver a generated artifact to a target (EXPLOIT - scope- and confirm-gated)."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet[/]")
        raise typer.Exit(1)
    state = _load_state(state_path)

    art = next((a for a in state.artifacts if a.name == artifact), None)
    if art is None:
        console.print(f"[bold red]no such artifact:[/] {artifact}")
        raise typer.Exit(1)

    if listen:
        lport = art.meta.get("lport", "4444")
        console.print(f"[bold]start a listener first:[/]  nc -lvnp {lport}\n")

    dm = method_by_name(method, interpreter=interpreter)
    scope = Scope.from_config(cfg.targets, cfg.exclude)
    validator = Validator(scope, {dm.binary}, cfg.effective_threshold)
    result = asyncio.run(deliver_artifact(dm, art, target, validator, confirm=_confirm))

    state.record_action(ActionRecord(
        phase=Phase.EXPLOIT, tool=f"deliver:{dm.name}", command=result.command,
        rationale=f"deliver {art.name} to {target}",
        approved=result.status not in ("blocked", "declined"),
        exit_code=result.run.exit_code if result.run else None,
    ))
    # Delivery output can carry a flag (e.g. a shell that read user.txt) - this is
    # an explicit exploit context, so accept bare 32-hex HTB flags too.
    if result.run:
        for captured in find_flags(result.run.stdout, include_bare_hex=True):
            if state.add_flag(captured):
                console.print(f"[bold green]flag[/] {captured}")
    state.save(state_path)

    style = "bold green" if result.ok else "bold red"
    console.print(f"[{style}]{result.status}[/] {result.reason}")
    if result.run and result.run.stderr.strip():
        console.print(result.run.stderr.strip()[:500])


@app.command(rich_help_panel="Reporting & audit")
def report(config: Path = typer.Argument(..., help="engagement YAML"),
           output: Path = typer.Option(None, help="output path (default: <engagement>/report.md)"),
           html: bool = typer.Option(False, "--html", help="also write a styled HTML report"),
           pdf: bool = typer.Option(False, "--pdf", help="also write a PDF next to the Markdown")):
    """Render a Markdown report (optionally HTML/PDF) from the engagement state."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run a phase first[/]")
        raise typer.Exit(1)

    state = _load_state(state_path)
    markdown = render_markdown(state, audit_path=work / "audit.jsonl")
    out_path = output or (work / "report.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    console.print(f"[bold green]report[/] {out_path}")

    if html:
        from .report.html import render_html
        html_path = out_path.with_suffix(".html")
        html_path.write_text(render_html(state), encoding="utf-8")
        console.print(f"[bold green]report[/] {html_path}")

    if pdf:
        _write_pdf(markdown, out_path.with_suffix(".pdf"), cfg.name)


if __name__ == "__main__":
    app()
