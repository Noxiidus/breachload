"""Small host/URL helpers shared across adapters — IPv6-aware.

A raw IPv6 literal (``dead:beef::1``) must be wrapped in brackets before it goes
into a URL or a ``host:port`` string, or the colons are ambiguous and the URL is
malformed (``http://::1:80`` is meaningless). These helpers centralise that so an
IPv6 target flows through recon/enum/fingerprint the same way an IPv4 one does.
"""

from __future__ import annotations

import ipaddress


def is_ipv6(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host.strip("[]")),
                          ipaddress.IPv6Address)
    except ValueError:
        return False


def bracket(host: str) -> str:
    """Wrap a bare IPv6 literal in ``[]``; leave IPv4/hostnames (and already-bracketed) as-is."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        return h
    return f"[{h}]" if is_ipv6(h) else h


def host_port(host: str, port: int) -> str:
    """``host:port`` with the host IPv6-bracketed when needed."""
    return f"{bracket(host)}:{port}"


def host_url(host: str, port: int, scheme: str = "http") -> str:
    """A well-formed ``scheme://host:port`` URL, IPv6-safe."""
    return f"{scheme}://{bracket(host)}:{port}"
