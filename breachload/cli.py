"""breachload CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from .core.config import EngagementConfig
from .core.llm import Planner
from .core.orchestrator import Orchestrator
from .core.state import EngagementState, Phase
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
    validator = Validator(scope, allowed_binaries(registry), cfg.auto_risk)
    planner = Planner()
    audit = AuditLog(work / "audit.jsonl")

    mode = "online (Claude)" if planner.online else "offline (heuristic)"
    label = f"phase={phase}" if phase else f"auto → {stop}"
    console.print(f"[bold]breachload[/] — {cfg.name} | {label} | planner={mode}")
    console.print(state.summary())
    console.print()

    orch = Orchestrator(cfg, state, registry, validator, planner, audit,
                        state_path, confirm=_confirm, on_event=_emit)
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


if __name__ == "__main__":
    app()
