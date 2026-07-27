"""Engagement configuration.

An engagement is defined by a YAML file: scope, autonomy level, and metadata.
This is the single source of truth for what the agent is allowed to touch.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from ..safety.validator import Risk


class EngagementConfig(BaseModel):
    name: str
    targets: list[str] = Field(default_factory=list)     # IPs, CIDRs, domains
    exclude: list[str] = Field(default_factory=list)
    # Actions at or below this risk run without asking in full-auto mode.
    # CTF: ACTIVE or higher. Real engagement: keep at RECON and confirm the rest.
    auto_threshold: str = "active"
    mode: str = "full-auto"          # advisor | semi-auto | full-auto
    notes: str = ""

    @property
    def auto_risk(self) -> Risk:
        return Risk[self.auto_threshold.upper()]

    @property
    def effective_threshold(self) -> Risk | None:
        """The confirmation threshold, combining `mode` and `auto_threshold`.

        None means "confirm everything" (advisor). Otherwise actions at or below
        the returned risk run without asking; anything above needs confirmation.
        """
        mode = self.mode.lower()
        if mode == "advisor":
            return None                 # nothing runs without a human yes
        if mode == "semi-auto":
            return Risk.RECON           # passive/recon auto; the rest asks
        return self.auto_risk           # full-auto: use the configured threshold

    @classmethod
    def load(cls, path: Path) -> EngagementConfig:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls.model_validate(data)
