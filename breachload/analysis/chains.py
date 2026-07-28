"""Attack-chain templates.

Matches known machine profiles (legacy Windows SMB, anonymous FTP, Tomcat
manager, path-traversal, ...) against the state and returns ready-made,
multi-step playbooks. Data-driven (`data/chains.json`) and fully offline — this
is the closest thing to "autopilot" without an LLM: recognizable situations map
to concrete plans.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources

from ..core.state import EngagementState

_PLACEHOLDERS = ("LHOST", "LPORT", "TARGET", "PORT")


@dataclass
class Chain:
    id: str
    name: str
    priority: int
    when: dict
    steps: list[str] = field(default_factory=list)

    def render_steps(self, **ctx: object) -> list[str]:
        out = []
        for step in self.steps:
            for key in _PLACEHOLDERS:
                if key in ctx and ctx[key] is not None:
                    step = step.replace("{" + key + "}", str(ctx[key]))
            out.append(step)
        return out


class ChainMatcher:
    def __init__(self, chains: list[Chain]) -> None:
        self.chains = chains

    @classmethod
    def default(cls) -> ChainMatcher:
        raw = json.loads(
            resources.files("breachload.data").joinpath("chains.json").read_text(encoding="utf-8")
        )
        chains = [
            Chain(id=c["id"], name=c["name"], priority=c.get("priority", 5),
                  when=c.get("when", {}), steps=c.get("steps", []))
            for c in raw.get("chains", [])
        ]
        return cls(chains)

    def match(self, state: EngagementState) -> list[Chain]:
        matched = [c for c in self.chains if self._matches(c.when, state)]
        matched.sort(key=lambda c: c.priority)
        return matched

    def target_for(self, chain: Chain, state: EngagementState) -> str:
        """Pick the most relevant host address for rendering a matched chain."""
        ports = chain.when.get("service_ports")
        for host in state.hosts.values():
            if ports and any(s.port in ports for s in host.services.values()):
                return host.address
        return next(iter(state.hosts), "<target>")

    def _matches(self, when: dict, state: EngagementState) -> bool:
        conditions: list[bool] = []
        hosts = list(state.hosts.values())

        if "service_ports" in when:
            ports = set(when["service_ports"])
            conditions.append(any(s.port in ports for h in hosts for s in h.services.values()))
        if "os_contains" in when:
            needle = when["os_contains"].lower()
            conditions.append(any(needle in (h.os_guess or "").lower() for h in hosts))
        if "product_contains" in when:
            needle = when["product_contains"].lower()
            conditions.append(
                any(needle in (s.product or "").lower() for h in hosts for s in h.services.values())
            )
        if "finding_contains" in when:
            needle = when["finding_contains"].lower()
            conditions.append(any(needle in f.title.lower() for f in state.findings))

        return bool(conditions) and all(conditions)
