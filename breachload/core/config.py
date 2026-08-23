"""Engagement configuration.

An engagement is defined by a YAML file: scope, autonomy level, and metadata.
This is the single source of truth for what the agent is allowed to touch.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from ..safety.validator import Risk

_VALID_MODES = ("advisor", "semi-auto", "full-auto")


class EngagementConfig(BaseModel):
    name: str
    targets: list[str] = Field(default_factory=list)     # IPs, CIDRs, domains
    exclude: list[str] = Field(default_factory=list)
    # Actions at or below this risk run without asking in full-auto mode.
    # CTF: ACTIVE or higher. Real engagement: keep at RECON and confirm the rest.
    auto_threshold: str = "active"
    mode: str = "full-auto"          # advisor | semi-auto | full-auto
    ctf: bool = False                # CTF mode: aggressive defaults + flag capture
    # Attacker listener, used to fill LHOST/LPORT in rendered payloads and the
    # attack plan. A CLI --lhost/--lport still overrides these per-invocation.
    lhost: str = ""
    lport: int = 4444
    # Recon depth. full_ports scans all 65535 TCP ports (-p-) instead of the
    # default top-1000; it auto-enables in CTF mode where boxes hide services on
    # high ports. web_extensions (comma-separated, e.g. "php,txt,html") makes ffuf
    # also fuzz those file extensions.
    full_ports: bool = False
    web_extensions: str = ""
    # udp_scan adds a top-ports UDP pass in recon (SNMP/DNS/TFTP/IKE hide on UDP).
    # It needs root (raw sockets); without it nmap simply returns nothing and the
    # scan is skipped gracefully. ffuf_recursion makes content discovery recurse
    # into discovered directories up to recursion_depth levels.
    udp_scan: bool = False
    ffuf_recursion: bool = False
    recursion_depth: int = 1
    # Minimum seconds between executed actions (0 = no throttle). Keeps the agent
    # from hammering a target.
    min_action_interval: float = 0.0
    # --- auto-exploit mode (authorized, audited, scope-absolute) ----------------
    # auto_exploit lets the engine run autonomously through exploitation and post-
    # exploitation without per-action confirmation (up to EXPLOIT; DESTRUCTIVE is
    # always still confirmed, and off-scope is always hard-blocked). It only takes
    # effect when `authorized` is also true AND the running operator passes the
    # operator gate (see core/authz.py) — otherwise the engine falls back to the
    # normal confirm-gated behaviour.
    auto_exploit: bool = False
    # Per-engagement attestation that you have written authorization for this scope.
    # Required for auto_exploit to activate — a deliberate, conscious opt-in.
    authorized: bool = False
    notes: str = ""

    @field_validator("auto_threshold")
    @classmethod
    def _check_threshold(cls, v: str) -> str:
        if v.upper() not in Risk.__members__:
            valid = ", ".join(r.name.lower() for r in Risk)
            raise ValueError(f"invalid auto_threshold {v!r} (choose one of: {valid})")
        return v

    @field_validator("mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v.lower() not in _VALID_MODES:
            raise ValueError(f"invalid mode {v!r} (choose one of: {', '.join(_VALID_MODES)})")
        return v

    @property
    def scan_all_ports(self) -> bool:
        """Full-port TCP recon: explicit opt-in, or implied by CTF mode."""
        return self.full_ports or self.ctf

    @property
    def auto_risk(self) -> Risk:
        try:
            return Risk[self.auto_threshold.upper()]
        except KeyError:
            valid = ", ".join(r.name.lower() for r in Risk)
            raise ValueError(
                f"invalid auto_threshold {self.auto_threshold!r} "
                f"(choose one of: {valid})"
            ) from None

    @property
    def effective_threshold(self) -> Risk | None:
        """The confirmation threshold, combining `ctf`, `mode` and `auto_threshold`.

        None means "confirm everything" (advisor). Otherwise actions at or below
        the returned risk run without asking; anything above needs confirmation.
        """
        if self.ctf:
            return Risk.EXPLOIT         # CTF: run right up to exploitation
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
