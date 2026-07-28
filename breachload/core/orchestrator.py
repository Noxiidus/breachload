"""Orchestrator — the reasoning loop that ties everything together.

  state -> planner decides -> safety validates -> tool runs -> parser updates
  state -> audit logs -> repeat

The planner (LLM) only decides. Parsing and scope live in deterministic code.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from pathlib import Path

from ..analysis.analyzer import Analyzer
from ..analysis.flags import find_flags
from ..safety.audit import AuditLog
from ..safety.validator import Validator
from ..tools.base import ToolAdapter, ToolResult
from .config import EngagementConfig
from .llm import Planner
from .ratelimit import RateLimiter
from .state import ActionRecord, EngagementState, Phase

# The automatic progression. Exploitation and beyond are intentionally excluded:
# they require human intent even in full-auto, so the chain stops before them.
PHASE_ORDER = [Phase.RECON, Phase.ENUM, Phase.VULN]


class Orchestrator:
    def __init__(
        self,
        config: EngagementConfig,
        state: EngagementState,
        registry: dict[str, ToolAdapter],
        validator: Validator,
        planner: Planner,
        audit: AuditLog,
        state_path: Path,
        confirm: Callable[[str], bool] | None = None,
        on_event: Callable[[str, str], None] | None = None,
        analyzer: Analyzer | None = None,
        rate_limiter: RateLimiter | None = None,
        on_state: Callable[[EngagementState], None] | None = None,
    ) -> None:
        self.config = config
        self.state = state
        self.registry = registry
        self.validator = validator
        self.planner = planner
        self.audit = audit
        self.state_path = state_path
        # Enriches state with CVE matches and correlations after each step.
        self.analyzer = analyzer
        self.rate_limiter = rate_limiter
        # Pushed the current state after each step (e.g. to the web dashboard).
        self.on_state = on_state
        # confirm() is called for actions above the auto threshold. In advisor
        # mode everything routes through it; in full-auto only high-risk does.
        self.confirm = confirm or (lambda _: False)
        self.emit = on_event or (lambda ev, msg: None)
        self._stop = False

    def request_stop(self) -> None:
        """Kill-switch: stop the engagement after the current action."""
        self._stop = True
        self.emit("stopped", "kill-switch engaged — halting after current action")

    def _tool_catalog(self) -> list[dict]:
        return [
            {"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in self.registry.values()
        ]

    def _record(self, plan, command: list[str], *, approved: bool = True,
                exit_code: int | None = None) -> None:
        self.state.record_action(ActionRecord(
            phase=self.state.phase, tool=plan.tool or "?", command=command,
            rationale=plan.rationale, approved=approved, exit_code=exit_code,
        ))

    async def step(self) -> bool:
        """One decision+execution cycle. Returns False when the phase is done."""
        if self._stop:
            return False
        plan = self.planner.next_action(self.state, self._tool_catalog())
        self.audit.write("plan", phase=self.state.phase, plan=plan.__dict__)

        if plan.action != "run" or plan.tool is None:
            self.emit("phase", f"Phase {self.state.phase} complete: {plan.rationale}")
            return False

        adapter = self.registry.get(plan.tool)
        if adapter is None:
            self.emit("error", f"Unknown tool proposed: {plan.tool}")
            return False

        try:
            command = adapter.build_command(plan.target or "", **(plan.args or {}))
        except (TypeError, ValueError) as exc:
            self.emit("error", f"Bad command for {plan.tool}: {exc}")
            # Include the target so has_action() records this attempt and the
            # planner doesn't re-propose the same failing action in a loop.
            self._record(plan, [plan.tool, plan.target or ""], approved=False)
            return True

        decision = self.validator.check(command, adapter.risk)
        self.audit.write("validate", command=command, decision=decision.__dict__)

        if not decision.allowed:
            self.emit("blocked", f"BLOCKED: {' '.join(command)} — {decision.reason}")
            self._record(plan, command, approved=False)
            return True  # keep going; the planner may pick something else

        if decision.needs_confirmation:
            prompt = f"[{decision.risk.name}] {' '.join(command)}\n  why: {plan.rationale}"
            approved = self.confirm(prompt)
            if inspect.isawaitable(approved):   # supports async confirm (e.g. web UI)
                approved = await approved
            if not approved:
                self.emit("skipped", f"User declined: {' '.join(command)}")
                self._record(plan, command, approved=False)
                return True

        if self.rate_limiter is not None:
            await self.rate_limiter.wait()

        self.emit("run", f"$ {' '.join(command)}\n  why: {plan.rationale}")
        # A single tool failing (crash, timeout, unparseable output) must not
        # abort the whole engagement — log it, record it, and move on. The record
        # also stops the planner from re-proposing the same failing action.
        try:
            result = await adapter.run(command)
            notes = adapter.parse(result, self.state)
        except Exception as exc:  # noqa: BLE001 — deliberately broad: isolate tool failures
            self.emit("error", f"{plan.tool} failed: {exc}")
            self._record(plan, command, exit_code=-1)
            self.audit.write("tool_error", command=command, error=str(exc))
            self.state.save(self.state_path)
            return True

        for n in notes:
            self.emit("note", n)

        self._record(plan, command, exit_code=result.exit_code)
        self.audit.write("executed", command=command, exit_code=result.exit_code, notes=notes)

        if self.config.ctf:
            self._capture_flags(result, notes)

        if self.analyzer is not None:
            for f in self.analyzer.analyze(self.state):
                self.emit("finding", f"[{f.severity.value}] {f.title}")
                self.audit.write("finding", title=f.title, severity=f.severity.value,
                                 host=f.host, cve=f.cve)

        self.state.save(self.state_path)
        if self.on_state is not None:
            self.on_state(self.state)
        return True

    def _capture_flags(self, result: ToolResult, notes: list[str]) -> None:
        haystack = "\n".join([result.stdout or "", result.output_file or "", *notes])
        for flag in find_flags(haystack):
            if self.state.add_flag(flag):
                self.emit("flag", f"captured {flag}")
                self.audit.write("flag", flag=flag)

    async def run_phase(self, max_steps: int = 50) -> None:
        for _ in range(max_steps):
            if self._stop or not await self.step():
                break
            await asyncio.sleep(0)

    async def run_engagement(self, stop_after: Phase = Phase.VULN,
                             max_steps: int = 50) -> None:
        """Walk the phases automatically from the current one up to `stop_after`.

        This is the "guide me from recon to findings" experience: each phase runs
        to completion, then the next begins, all driven by state.
        """
        try:
            start = PHASE_ORDER.index(self.state.phase)
        except ValueError:
            start = 0
        for phase in PHASE_ORDER[start:]:
            if self._stop:
                break
            self.state.phase = phase
            self.emit("phase", f"== entering {phase.value} ==")
            self.state.save(self.state_path)
            await self.run_phase(max_steps=max_steps)
            if phase == stop_after:
                break
