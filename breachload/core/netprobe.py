"""Path-MTU / large-response stall probe.

A too-high VPN tun MTU (HTB pushes 1500) silently stalls every HTTP response
larger than ~1 MTU while tiny responses return instantly — which looks exactly
like "the app homepage hangs" and makes fingerprinting come back empty. This
probe distinguishes the two: it times a tiny ranged GET against a full GET. If
the small request succeeds fast but the full one stalls, MTU is the likely cause
and lowering tun0 to ~1300 is the fix.

Uses curl (single binary, always present on an attack box). Injectable runner for
tests; offline-safe (any failure yields an inconclusive verdict, never a crash).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class MtuProbeResult:
    ran: bool
    small_ok: bool
    large_ok: bool
    small_time: float
    large_time: float
    verdict: str
    suggestion: str


def _curl_argv(url: str, timeout: int, ranged: bool) -> list[str]:
    argv = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
            "--max-time", str(timeout), url]
    if ranged:
        # A tiny ranged request returns even when a full response stalls on MTU.
        argv[1:1] = ["-r", "0-2048"]
    return argv


def _parse(out: str) -> tuple[bool, float]:
    """(ok, seconds) from curl's '<http_code> <time_total>' write-out."""
    parts = (out or "").split()
    if len(parts) < 2:
        return False, 0.0
    try:
        code = int(parts[0])
        secs = float(parts[1])
    except ValueError:
        return False, 0.0
    return code > 0, secs


def probe_path_mtu(target: str, *, port: int = 80, scheme: str = "http",
                   timeout: int = 8, runner=None) -> MtuProbeResult:
    """Probe `target` for the large-response stall pattern."""
    if runner is None and shutil.which("curl") is None:
        return MtuProbeResult(False, False, False, 0.0, 0.0,
                              "curl not installed - cannot probe", "")
    runner = runner or _default_runner
    url = f"{scheme}://{target}:{port}/"

    small_ok, small_t = _parse(runner(_curl_argv(url, timeout, ranged=True)))
    large_ok, large_t = _parse(runner(_curl_argv(url, timeout, ranged=False)))

    if small_ok and not large_ok:
        verdict = ("small ranged GET succeeded but the full GET stalled - classic "
                   "MTU / large-response stall")
        suggestion = "sudo ip link set dev tun0 mtu 1300   # then re-run recon"
    elif not small_ok and not large_ok:
        verdict = "no response to either request - host down, filtered, or wrong port"
        suggestion = ""
    else:
        verdict = "both requests returned - path MTU looks fine"
        suggestion = ""
    return MtuProbeResult(True, small_ok, large_ok, small_t, large_t, verdict, suggestion)


def _default_runner(argv: list[str]) -> str:  # pragma: no cover - real subprocess
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""
