"""Tool adapter contract.

Each adapter knows how to (a) build a command line and (b) parse that tool's
output into structured state updates. Parsing lives here, in code — never in the
LLM. An adapter declares its binary, its risk class, and its capabilities so the
orchestrator and validator can reason about it.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..core.state import EngagementState
from ..safety.validator import Risk


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float


@dataclass
class ToolAdapter(ABC):
    """Base class for a wrapped tool."""

    name: str = ""
    binary: str = ""
    risk: Risk = Risk.RECON
    # Free-form tags the orchestrator matches against (e.g. "port-scan",
    # "http", "smb"). Lets the planner pick relevant tools per phase.
    capabilities: list[str] = field(default_factory=list)

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> list[str]:
        """Return an argv list (no shell). Must be scope-checkable."""

    @abstractmethod
    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        """Fold tool output into state. Return short human-readable notes."""

    async def run(self, command: list[str], timeout: float = 600.0) -> ToolResult:
        loop = asyncio.get_event_loop()
        start = loop.time()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            out, err = await proc.communicate()
            return ToolResult(-1, out.decode(errors="replace"),
                              "TIMEOUT\n" + err.decode(errors="replace"),
                              loop.time() - start)
        return ToolResult(
            proc.returncode if proc.returncode is not None else -1,
            out.decode(errors="replace"),
            err.decode(errors="replace"),
            loop.time() - start,
        )
