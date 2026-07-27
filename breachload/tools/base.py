"""Tool adapter contract.

Each adapter knows how to (a) build a command line and (b) parse that tool's
output into structured state updates. Parsing lives here, in code — never in the
LLM. An adapter declares its binary, its risk class, and its capabilities so the
orchestrator and validator can reason about it.

Some tools only emit machine-readable output to a file, not stdout. Such an
adapter puts the ``{OUTFILE}`` marker in its command and sets
``output_file_suffix``; ``run`` allocates a temp path, substitutes it, and reads
the resulting file back into ``ToolResult.output_file`` after execution. The
marker is a safe local placeholder, so scope validation (which runs on the
pre-substitution command) is unaffected.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..core.state import EngagementState
from ..safety.validator import Risk

OUTFILE_MARKER = "{OUTFILE}"


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    # Content of a tool-managed output file, when the adapter uses OUTFILE_MARKER.
    output_file: str | None = None


@dataclass
class ToolAdapter(ABC):
    """Base class for a wrapped tool."""

    name: str = ""
    binary: str = ""
    risk: Risk = Risk.RECON
    # Free-form tags the orchestrator matches against (e.g. "port-scan",
    # "http", "smb"). Lets the planner pick relevant tools per phase.
    capabilities: list[str] = field(default_factory=list)
    # If the tool writes structured output to a file, set the suffix it appends
    # to the OUTFILE_MARKER base path (e.g. ".json"). "" means the marker is the
    # file itself. None means the adapter reads stdout only.
    output_file_suffix: str | None = None

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> list[str]:
        """Return an argv list (no shell). Must be scope-checkable."""

    @abstractmethod
    def parse(self, result: ToolResult, state: EngagementState) -> list[str]:
        """Fold tool output into state. Return short human-readable notes."""

    async def run(self, command: list[str], timeout: float = 600.0) -> ToolResult:
        tmpdir: str | None = None
        base_path: str | None = None
        real_cmd = command
        if any(OUTFILE_MARKER in tok for tok in command):
            tmpdir = tempfile.mkdtemp(prefix="breachload_")
            base_path = str(Path(tmpdir) / "out")
            real_cmd = [tok.replace(OUTFILE_MARKER, base_path) for tok in command]

        loop = asyncio.get_event_loop()
        start = loop.time()
        try:
            result = await self._exec(real_cmd, timeout, start, loop)
            if base_path is not None:
                result.output_file = self._read_output_file(base_path)
            return result
        finally:
            if tmpdir is not None:
                shutil.rmtree(tmpdir, ignore_errors=True)

    async def _exec(self, command, timeout, start, loop) -> ToolResult:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
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

    def _read_output_file(self, base_path: str) -> str | None:
        target = Path(base_path + (self.output_file_suffix or ""))
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
