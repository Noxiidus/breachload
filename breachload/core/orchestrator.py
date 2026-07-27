"""Orchestrator — the reasoning loop that ties everything together.

  state -> planner decides -> safety validates -> tool runs -> parser updates
  state -> audit logs -> repeat

The planner (LLM) only decides. Parsing and scope live in deterministic code.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from ..safety.audit import AuditLog
from ..safety.validator import Validator
from ..tools.base import ToolAdapter
from .config import EngagementConfig
from .llm import Planner
from .state import ActionRecord, EngagementState


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
    ) -> None:
        self.config = config
        self.state = state
        self.registry = registry
        self.validator = validator
        self.planner = planner
        self.audit = audit
        self.state_path = state_path
        # confirm() is called for actions above the auto threshold. In advisor
        # mode everything routes through it; in full-auto only high-risk does.
        self.confirm = confirm or (lambda _: False)
        self.emit = on_event or (lambda ev, msg: None)

    def _tool_catalog(self) -> list[dict]:
        return [
            {"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in self.registry.values()
        ]

    async def step(self) -> bool:
        """One decision+execution cycle. Returns False when the phase is done."""
        plan = self.planner.next_action(self.state, self._tool_catalog())
        self.audit.write("plan", phase=self.state.phase, plan=plan.__dict__)

        if plan.action != "run" or plan.tool is None:
            self.emit("phase", f"Phase {self.state.phase} complete: {plan.rationale}")
            return False

        adapter = self.registry.get(plan.tool)
        if adapter is None:
            self.emit("error", f"Unknown tool proposed: {plan.tool}")
            return False

        command = adapter.build_command(plan.target or "", **(plan.args or {}))
        decision = self.validator.check(command, adapter.risk)
        self.audit.write("validate", command=command, decision=decision.__dict__)

        if not decision.allowed:
            self.emit("blocked", f"BLOCKED: {' '.join(command)} — {decision.reason}")
            self.state.record_action(ActionRecord(
                phase=self.state.phase, tool=plan.tool, command=command,
                rationale=plan.rationale, approved=False,
            ))
            return True  # keep going; the planner may pick something else

        if decision.needs_confirmation:
            prompt = f"[{decision.risk.name}] {' '.join(command)}\n  why: {plan.rationale}"
            if not self.confirm(prompt):
                self.emit("skipped", f"User declined: {' '.join(command)}")
                self.state.record_action(ActionRecord(
                    phase=self.state.phase, tool=plan.tool, command=command,
                    rationale=plan.rationale, approved=False,
                ))
                return True

        self.emit("run", f"$ {' '.join(command)}\n  why: {plan.rationale}")
        result = await adapter.run(command)
        notes = adapter.parse(result, self.state)
        for n in notes:
            self.emit("note", n)

        self.state.record_action(ActionRecord(
            phase=self.state.phase, tool=plan.tool, command=command,
            rationale=plan.rationale, exit_code=result.exit_code,
        ))
        self.audit.write("executed", command=command, exit_code=result.exit_code, notes=notes)
        self.state.save(self.state_path)
        return True

    async def run_phase(self, max_steps: int = 20) -> None:
        for _ in range(max_steps):
            if not await self.step():
                break
            await asyncio.sleep(0)
