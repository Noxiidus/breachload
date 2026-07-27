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
from .core.state import EngagementState, Phase
from .exploit.generators import GenerationError, MsfvenomGenerator, PayloadSpec
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


if __name__ == "__main__":
    app()
