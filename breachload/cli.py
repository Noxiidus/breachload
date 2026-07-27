"""breachload CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from .analysis.analyzer import Analyzer
from .core.config import EngagementConfig
from .core.llm import Planner
from .core.orchestrator import Orchestrator
from .core.state import ActionRecord, EngagementState, Phase
from .exploit.delivery import deliver_artifact, method_by_name
from .exploit.generators import GenerationError, MsfvenomGenerator, PayloadSpec
from .report.engine import render_markdown
from .report.pdf import render_pdf
from .safety.audit import AuditLog
from .safety.scope import Scope
from .safety.validator import Validator
from .tools.registry import allowed_binaries, default_registry

app = typer.Typer(help="breachload — autonomous pentest copilot", no_args_is_help=True)
console = Console()

ENGAGEMENTS = Path("engagements")

_STYLES = {
    "run": "bold cyan", "note": "green", "blocked": "bold red",
    "skipped": "yellow", "error": "bold red", "phase": "bold magenta",
    "finding": "bold yellow",
}


def _emit(event: str, msg: str) -> None:
    console.print(f"[{_STYLES.get(event, 'white')}]{event:>8}[/] {msg}")


def _confirm(prompt: str) -> bool:
    console.print(f"[yellow]confirm[/] {prompt}")
    return typer.confirm("  run this?", default=False)


@app.command()
def run(config: Path = typer.Argument(..., help="engagement YAML"),
        phase: str = typer.Option(None, help="run only this phase (recon/enumeration/vuln)"),
        stop: str = typer.Option("vuln_analysis", help="auto-chain stops after this phase")):
    """Run an engagement. By default auto-chains recon -> enumeration -> vuln."""
    cfg = EngagementConfig.load(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"

    if state_path.exists():
        state = EngagementState.load(state_path)
    else:
        state = EngagementState(name=cfg.name)
        for t in cfg.targets:
            if not any(c in t for c in "/*"):  # bare host/IP → seed a host record
                state.upsert_host(t)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    planner = Planner()
    audit = AuditLog(work / "audit.jsonl")

    planner_mode = "online (Claude)" if planner.online else "offline (heuristic)"
    label = f"phase={phase}" if phase else f"auto -> {stop}"
    console.print(f"[bold]breachload[/] — {cfg.name} | {label} | "
                  f"mode={cfg.mode} | planner={planner_mode}")
    console.print(state.summary())
    console.print()

    orch = Orchestrator(cfg, state, registry, validator, planner, audit,
                        state_path, confirm=_confirm, on_event=_emit,
                        analyzer=Analyzer.default())
    if phase:
        state.phase = Phase(phase)
        asyncio.run(orch.run_phase())
    else:
        asyncio.run(orch.run_engagement(stop_after=Phase(stop)))

    state.save(state_path)
    console.print()
    console.print(state.summary())


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
        console.print("[bold red]web extra not installed[/] — run: pip install 'breachload[web]'")
        raise typer.Exit(1) from None

    cfg = EngagementConfig.load(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if state_path.exists():
        state = EngagementState.load(state_path)
    else:
        state = EngagementState(name=cfg.name)
        for t in cfg.targets:
            if not any(c in t for c in "/*"):
                state.upsert_host(t)

    scope = Scope.from_config(cfg.targets, cfg.exclude)
    registry = default_registry()
    validator = Validator(scope, allowed_binaries(registry), cfg.effective_threshold)
    audit = AuditLog(work / "audit.jsonl")
    hub = EventHub()
    orch = Orchestrator(cfg, state, registry, validator, Planner(), audit, state_path,
                        confirm=hub.request_confirm, on_event=hub.emit,
                        analyzer=Analyzer.default())

    async def _boot():
        async def _run():
            if phase:
                state.phase = Phase(phase)
                await orch.run_phase()
            else:
                await orch.run_engagement(stop_after=Phase(stop))
            state.save(state_path)
        asyncio.create_task(_run())

    web_app = create_app(hub, state_path, on_startup=_boot)
    console.print(f"[bold]breachload[/] dashboard: http://{host}:{port}  (engagement: {cfg.name})")
    uvicorn.run(web_app, host=host, port=port, log_level="warning")


@app.command()
def status(config: Path = typer.Argument(..., help="engagement YAML")):
    """Show current known state for an engagement."""
    cfg = EngagementConfig.load(config)
    state_path = ENGAGEMENTS / cfg.name / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet — run a phase first[/]")
        raise typer.Exit(1)
    console.print(EngagementState.load(state_path).summary())


@app.command()
def payload(config: Path = typer.Argument(..., help="engagement YAML"),
            payload: str = typer.Option(..., help="msfvenom payload type"),
            lhost: str = typer.Option(..., help="your listener host (attacker IP)"),
            lport: int = typer.Option(4444, help="listener port"),
            fmt: str = typer.Option("elf", help="output format (-f): elf, exe, raw, python, ..."),
            name: str = typer.Option(None, help="artifact filename")):
    """Generate a payload artifact with msfvenom (offline — no target, no scope check)."""
    cfg = EngagementConfig.load(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if state_path.exists():
        state = EngagementState.load(state_path)
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
def deliver(config: Path = typer.Argument(..., help="engagement YAML"),
            artifact: str = typer.Option(..., help="artifact name (see `status`)"),
            target: str = typer.Option(..., help="target host or URL (must be in scope)"),
            method: str = typer.Option("script", help="delivery method: script | upload"),
            interpreter: str = typer.Option("python3", help="interpreter for the script method")):
    """Deliver a generated artifact to a target (EXPLOIT — scope- and confirm-gated)."""
    cfg = EngagementConfig.load(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet[/]")
        raise typer.Exit(1)
    state = EngagementState.load(state_path)

    art = next((a for a in state.artifacts if a.name == artifact), None)
    if art is None:
        console.print(f"[bold red]no such artifact:[/] {artifact}")
        raise typer.Exit(1)

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
    cfg = EngagementConfig.load(config)
    work = ENGAGEMENTS / cfg.name
    state_path = work / "state.json"
    if not state_path.exists():
        console.print("[yellow]no state yet — run a phase first[/]")
        raise typer.Exit(1)

    state = EngagementState.load(state_path)
    markdown = render_markdown(state)
    out_path = output or (work / "report.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    console.print(f"[bold green]report[/] {out_path}")

    if pdf:
        pdf_path = out_path.with_suffix(".pdf")
        pdf_path.write_bytes(render_pdf(markdown, title=f"breachload — {cfg.name}"))
        console.print(f"[bold green]report[/] {pdf_path}")


if __name__ == "__main__":
    app()
