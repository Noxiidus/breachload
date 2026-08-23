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
from .state import ActionRecord, EngagementState, Finding, Phase, Severity

# The default automatic progression. Exploitation and beyond are excluded: they
# require human intent, so the chain stops before them.
PHASE_ORDER = [Phase.RECON, Phase.ENUM, Phase.VULN]
# The auto-exploit progression continues autonomously through exploitation and
# post-exploitation. Only reachable behind the authorized, audited auto-exploit
# gate (see core/authz.py); scope is still hard-enforced and DESTRUCTIVE actions
# still require a human, even here.
AUTO_EXPLOIT_ORDER = [Phase.RECON, Phase.ENUM, Phase.VULN, Phase.EXPLOIT, Phase.POST]


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
        auto_exploit: bool = False,
        dry_run: bool = False,
        session=None,
    ) -> None:
        self.config = config
        # A foothold command-execution channel (webshell/ssh). When present in
        # auto-exploit mode, the POST phase autonomously enumerates and escalates
        # privileges through it. Its host must be in scope.
        self.session = session
        # Dry-run: validate and show what WOULD run, but never execute (a safe
        # preview for learners). Actions are recorded so the planner advances.
        self.dry_run = dry_run
        # Autonomous exploitation/post-exploitation. Set ONLY after the auto-exploit
        # authorization gate has passed (the CLI enforces this); it merely extends
        # the auto-walk — scope and DESTRUCTIVE gating are unchanged.
        self.auto_exploit = auto_exploit
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

    def _prune_retryable_history(self) -> None:
        """Remove safety-blocked / declined actions (approved=False, no exit code) so a
        new run re-evaluates them against the current scope and confirmation."""
        self.state.history = [
            a for a in self.state.history
            if a.approved or a.exit_code is not None
        ]

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
            # exit_code=-1 marks it as a real (permanent) failure so it survives the
            # start-of-run prune of merely safety-blocked actions.
            self._record(plan, [plan.tool, plan.target or ""], approved=False, exit_code=-1)
            return True

        decision = self.validator.check(command, adapter.risk)
        self.audit.write("validate", command=command, decision=decision.__dict__)

        if not decision.allowed:
            self.emit("blocked", f"BLOCKED: {' '.join(command)} — {decision.reason}")
            self._record(plan, command, approved=False)
            return True  # keep going; the planner may pick something else

        if self.dry_run:
            # Show what would run (regardless of the confirm threshold) and record
            # it so the planner moves on, but never touch the target.
            self.emit("run", f"DRY-RUN would run: $ {' '.join(command)}\n  why: {plan.rationale}")
            self._record(plan, command)
            return True

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
        to completion, then the next begins, all driven by state. In auto-exploit
        mode the walk continues through exploitation and post-exploitation.
        """
        # A safety-blocked or user-declined action was recorded only to prevent an
        # in-run re-propose loop; it must not suppress a retry on a *later* run whose
        # scope or confirmation may differ (e.g. a vhost added to scope between runs).
        # Drop those (approved=False, exit_code is None) at the start of each run;
        # executed actions and permanent build failures (exit_code set) are kept.
        self._prune_retryable_history()

        order = AUTO_EXPLOIT_ORDER if self.auto_exploit else PHASE_ORDER
        if self.state.phase in order:
            start = order.index(self.state.phase)
        elif self.state.phase == Phase.SCOPING:
            start = 0                       # fresh engagement: begin at recon
        else:
            # Already past the auto-walk. Don't rewind the phase — nothing left.
            return
        for phase in order[start:]:
            if self._stop:
                break
            self.state.phase = phase
            self.emit("phase", f"== entering {phase.value} ==")
            self.state.save(self.state_path)
            if phase == Phase.POST and self.auto_exploit and self.session is not None:
                self._autonomous_privesc()
            else:
                await self.run_phase(max_steps=max_steps)
                # After the read-only probes, try to auto-establish a foothold from a
                # matching KB CVE, so the POST phase has a session to escalate through.
                if phase == Phase.EXPLOIT and self.auto_exploit and self.session is None:
                    self._auto_foothold()
            if phase == stop_after:
                break

    def _auto_foothold(self) -> None:
        """Fire a coded auto-foothold module for a matching finding and, on success,
        register the resulting session for the POST phase. Auto-exploit mode only."""
        from ..exploit.footholds import foothold_for

        for f in self.state.findings:
            for cve in f.cve:
                module = foothold_for(cve)
                if module is None or not f.host:
                    continue
                if not self.validator.scope.allows(f.host):
                    continue
                head = (f.service_key or "").split("/", 1)[0]
                port = int(head) if head.isdigit() else 80
                scheme = "https" if port in (443, 8443) else "http"
                self.emit("run", f"auto-foothold: {module.name} on {f.host}:{port}")
                self.audit.write("auto_foothold", cve=cve, host=f.host, port=port)
                session = module.establish(f.host, port, scheme=scheme)
                if session is not None:
                    self.session = session
                    self.emit("finding", f"[critical] Foothold established via {module.name}")
                    self.state.add_finding(Finding(
                        title=f"Foothold established: {module.name}",
                        severity=Severity.CRITICAL, host=f.host, cve=[cve],
                        description="Autonomous auto-foothold module gained code execution "
                                    "and opened a session for post-exploitation.",
                    ))
                    self.state.save(self.state_path)
                    return
                self.emit("note", f"auto-foothold {cve} did not land; foothold stays guided")

    def _autonomous_privesc(self) -> None:
        """Drive privilege escalation through the foothold session: enumerate, parse,
        and fire a curated escalation, all audited. Only in auto-exploit mode."""
        from ..analysis.privesc_auto import attempt_escalation, run_enum

        session = self.session
        if not self.validator.scope.allows(session.host):
            self.emit("blocked", f"session host {session.host} is out of scope — refusing")
            return
        self.emit("run", f"autonomous privesc via session on {session.host}")
        self.audit.write("session_enum", host=session.host)

        findings, creds, raw = run_enum(session)
        existing_titles = {f.title for f in self.state.findings}
        existing_creds = {(c.username, c.secret, c.kind) for c in self.state.credentials}
        for f in findings:
            if f.title not in existing_titles:
                self.state.add_finding(f)
                self.emit("finding", f"[{f.severity.value}] {f.title}")
        for c in creds:
            if (c.username, c.secret, c.kind) not in existing_creds:
                self.state.credentials.append(c)

        result = attempt_escalation(session, raw, findings)
        self.audit.write("session_escalation", method=result.method,
                         escalated=result.escalated)
        if result.escalated:
            self.emit("finding", f"[critical] Root via {result.method}")
            self.state.add_finding(Finding(
                title=f"Privilege escalation to root via {result.method}",
                severity=Severity.CRITICAL, host=session.host,
                description="Autonomous escalation confirmed by reading the root proof file.",
                evidence=result.evidence,
            ))
            if result.root_flag and self.state.add_flag(result.root_flag):
                self.emit("flag", f"captured {result.root_flag}")
                self.audit.write("flag", flag=result.root_flag)
        else:
            self.emit("note", f"no auto-escalation ({result.evidence}); "
                              "see the privesc playbook in the plan")
        self.state.save(self.state_path)
