"""Resilient curl fetch policy — one place that knows how to GET a page reliably.

The recurring field failure is a large or slow HTTP response that stalls (a too-high
VPN tun MTU, a throttled app, a streaming body) so a plain ``curl`` hangs until the
timeout and the adapter comes back empty. This module encodes the mitigations as a
pure argv builder (no I/O, trivially testable):

* ``--retry`` with ``--retry-connrefused`` so a transient reset/refuse self-heals;
* a byte cap via a ``Range: 0-<n>`` request so we pull just the head of a page — all
  a fingerprinter needs — instead of waiting on a giant body that would stall;
* an explicit ``--max-time`` ceiling so a genuine stall aborts with partial output
  (still parseable) rather than blocking the whole run.

argv-only, no shell — the same discipline the tool adapters use.
"""

from __future__ import annotations


def fetch_argv(
    url: str,
    *,
    follow: bool = True,
    include_headers: bool = False,
    max_bytes: int | None = None,
    timeout: int = 20,
    retries: int = 2,
    retry_delay: int = 1,
) -> list[str]:
    """Build a curl argv that fetches ``url`` resiliently.

    ``max_bytes`` caps the response with a byte-range request: enough to fingerprint
    without stalling on a large body. ``retries`` covers transient connection errors.
    """
    argv = ["curl", "-s"]
    if follow:
        argv.append("-L")
    if include_headers:
        argv.append("-i")
    if max_bytes and max_bytes > 0:
        # Ask for only the first max_bytes; if the server ignores Range it still
        # streams, but --max-time then caps it and stdout keeps the usable head.
        argv += ["-r", f"0-{max_bytes}"]
    if retries and retries > 0:
        argv += ["--retry", str(retries),
                 "--retry-delay", str(retry_delay),
                 "--retry-connrefused"]
    argv += ["--max-time", str(timeout), url]
    return argv
