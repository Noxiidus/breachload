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
                      "— add them to /etc/hosts to enumerate, or they'll be picked up "
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


@app.command()
def run(config: Path = typer.Argument(..., help="engagement YAML"),
        phase: str = typer.Option(None, help="run only this phase (recon/enumeration/vuln)"),
        stop: str = typer.Option("vuln_analysis", help="auto-chain stops after this phase")):
    """Run an engagement. By default auto-chains recon -> enumeration -> vuln."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_or_seed_state(cfg, state_path)
    _warn_if_no_hosts(state, cfg)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    planner = Planner()
    audit = AuditLog(work / "audit.jsonl")

    planner_mode = "online (Claude)" if planner.online else "offline (heuristic)"
    label = f"phase={phase}" if phase else f"auto -> {stop}"
    console.print(f"[bold]breachload[/] - {cfg.name} | {label} | "
                  f"mode={cfg.mode} | planner={planner_mode}")
    console.print(state.summary())
    console.print()

    orch = Orchestrator(cfg, state, registry, validator, planner, audit,
                        state_path, confirm=_confirm, on_event=_emit,
                        analyzer=Analyzer.default())
    if phase:
        state.phase = _parse_phase(phase)
        asyncio.run(orch.run_phase())
    else:
        asyncio.run(orch.run_engagement(stop_after=_parse_phase(stop)))

    state.save(state_path)
    console.print()
    console.print(state.summary())


@app.command()
def auto(config: Path = typer.Argument(..., help="engagement YAML"),
         lhost: str = typer.Option("LHOST", help="your listener host for the attack plan"),
         lport: int = typer.Option(4444, help="listener port for the attack plan"),
         stop: str = typer.Option("vuln_analysis", help="auto-chain stops after this phase"),
         pdf: bool = typer.Option(True, "--pdf/--no-pdf", help="also write a PDF report")):
    """Autopilot: recon -> enum -> vuln, then print an attack plan and write a report.

    One command, no API key needed. Safe recon/enumeration/vuln scanning runs
    automatically (anything above the threshold still asks); then the rule-based
    engine prints exactly what to try next, and a report is written.
    """
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    state = _load_or_seed_state(cfg, state_path)
    _warn_if_no_hosts(state, cfg)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    planner = Planner()
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


@app.command()
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
    orch = Orchestrator(cfg, state, registry, validator, Planner(), audit, state_path,
                        confirm=hub.request_confirm, on_event=hub.emit,
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


@app.command()
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


@app.command()
def suggest(config: Path = typer.Argument(..., help="engagement YAML"),
            lhost: str = typer.Option("LHOST", help="your listener host for rendered payloads"),
            lport: int = typer.Option(4444, help="listener port")):
    """Rule-based next-step plan from the current state (works with no API key)."""
    cfg = _load_config(config)
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


@app.command(name="kb-import")
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


@app.command()
def doctor():
    """Check which external tools and wordlists are available on this machine."""
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


@app.command()
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


@app.command()
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


@app.command()
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


@app.command()
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


@app.command()
def status(config: Path = typer.Argument(..., help="engagement YAML")):
    """Show current known state for an engagement."""
    cfg = _load_config(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run a phase first[/]")
        raise typer.Exit(1)
    console.print(_load_state(state_path).summary())


@app.command()
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


@app.command()
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


@app.command()
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


@app.command()
def report(config: Path = typer.Argument(..., help="engagement YAML"),
           output: Path = typer.Option(None, help="output path (default: <engagement>/report.md)"),
           pdf: bool = typer.Option(False, "--pdf", help="also write a PDF next to the Markdown")):
    """Render a Markdown report (and optionally PDF) from the engagement state."""
    cfg = _load_config(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet - run a phase first[/]")
        raise typer.Exit(1)

    state = _load_state(state_path)
    markdown = render_markdown(state)
    out_path = output or (work / "report.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    console.print(f"[bold green]report[/] {out_path}")

    if pdf:
        _write_pdf(markdown, out_path.with_suffix(".pdf"), cfg.name)


if __name__ == "__main__":
    app()
