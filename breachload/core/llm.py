"""LLM reasoning layer (Claude).

The model's job is narrow and well-defined: given the structured state summary
and the list of available tools, decide the next action and explain why. It does
NOT parse output and it does NOT get to bypass the safety layer — whatever it
proposes is validated in code before running.

The client is optional: if no API key is configured, breachload falls back to a
deterministic heuristic planner so the whole pipeline still runs offline.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .state import EngagementState, Phase

SYSTEM_PROMPT = """You are the planning core of breachload, an autonomous pentest \
assistant operating strictly inside an authorized engagement scope.

You are given a structured summary of what is currently known about the target(s) \
and a list of available tools. Decide the single best next action.

Rules:
- Propose exactly one tool invocation, or signal that the current phase is complete.
- You never invent hosts, ports, or services — reason only from the provided state.
- You explain your reasoning concisely: what you expect to learn and why now.
- Scope and command safety are enforced by a separate deterministic layer; do not \
worry about it, just propose the technically best next step.

Respond ONLY with JSON:
{"action": "run|phase_complete", "tool": "<name>", "target": "<host>", \
"args": {...}, "rationale": "<one or two sentences>"}"""


@dataclass
class Plan:
    action: str                  # "run" | "phase_complete"
    tool: str | None = None
    target: str | None = None
    args: dict | None = None
    rationale: str = ""


class Planner:
    """Wraps Claude, with a heuristic fallback when no key is present."""

    def __init__(self, model: str = "claude-opus-5") -> None:
        self.model = model
        self._client = None
        key = os.environ.get("ANTHROPIC_API_KEY")
        if key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=key)
            except ImportError:
                self._client = None

    @property
    def online(self) -> bool:
        return self._client is not None

    def next_action(self, state: EngagementState, tools: list[dict]) -> Plan:
        if self._client is None:
            return self._heuristic(state, tools)
        user = json.dumps({
            "state": state.summary(),
            "phase": state.phase,
            "tools": tools,
        }, indent=2)
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user}],
        )
        text = msg.content[0].text.strip()
        return self._parse_plan(text, state, tools)

    def _parse_plan(self, text: str, state: EngagementState, tools: list[dict]) -> Plan:
        try:
            start, end = text.index("{"), text.rindex("}") + 1
            data = json.loads(text[start:end])
            return Plan(
                action=data.get("action", "phase_complete"),
                tool=data.get("tool"),
                target=data.get("target"),
                args=data.get("args") or {},
                rationale=data.get("rationale", ""),
            )
        except (ValueError, json.JSONDecodeError):
            return self._heuristic(state, tools)

    def _heuristic(self, state: EngagementState, tools: list[dict]) -> Plan:
        """Zero-LLM planner: enough to drive recon end-to-end for testing."""
        if state.phase == Phase.RECON:
            for host in state.hosts.values():
                if not host.services:
                    return Plan("run", "nmap", host.address, {},
                                "No services known yet; run a service scan.")
            return Plan("phase_complete", rationale="All hosts have been scanned.")
        return Plan("phase_complete", rationale="No heuristic for this phase yet.")
