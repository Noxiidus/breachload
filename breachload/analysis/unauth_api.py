"""Generalized unauthenticated admin/API detector.

The NiFi lesson - `supportsLogin: false` on `/nifi-api/access/config` meant the
whole REST API was unauthenticated - is one instance of a broader class: a
management/API endpoint that returns real data (users, config, actuator info) to
an unauthenticated caller. This module probes a curated list of high-signal
management paths across common stacks and flags the class-level primitive when
one answers with real content.

Pure command generation + response classification (no I/O in this module), so it
works on any target that fits the pattern. The pattern - not any specific app -
is what generalizes.
"""

from __future__ import annotations

import re

from ..core.state import Finding, Severity

# Curated management/API paths that leak or expose actions when reachable without
# authentication. Each entry: path -> (why-it-matters, evidence-marker regex).
# The regex marks the response as REAL data (vs a generic 200/HTML index), which
# is what turns a suspected reach into a confirmed unauth-admin finding.
UNAUTH_PATHS: dict[str, tuple[str, str]] = {
    # Apache NiFi (the class exemplar).
    "/nifi-api/access/config":
        ("NiFi access config - supportsLogin:false means the whole REST API is unauthenticated",
         r'"supportsLogin"\s*:\s*false'),
    "/nifi-api/flow/about":
        ("NiFi flow/about - version + build (probe /nifi-api/access/config next)",
         r'"about"\s*:\s*\{.*?"version"'),
    # Spring Boot actuator - notorious for exposing env/heapdump/mappings.
    "/actuator":
        ("Spring Boot actuator index - unauth links to env/heapdump/mappings",
         r'"_links"\s*:\s*\{'),
    "/actuator/env":
        ("Spring Boot actuator /env - leaks system+app env, often secrets",
         r'"activeProfiles"|"propertySources"'),
    "/actuator/heapdump":
        ("Spring Boot actuator heapdump - download and grep for secrets",
         r".*"),
    "/actuator/mappings":
        ("Spring Boot actuator /mappings - full request-mapping table",
         r'"contexts"|"mappings"'),
    # Elasticsearch / Kibana - default no-auth on many older deployments.
    "/_cluster/health":
        ("Elasticsearch cluster health without auth - full cluster reachable",
         r'"cluster_name"|"status"\s*:\s*"(?:green|yellow|red)"'),
    "/_cat/indices":
        ("Elasticsearch /_cat/indices without auth - list every index",
         r"(?m)^(?:yellow|green|red)\s"),
    # Kubernetes API + kubelet.
    "/api/v1":
        ("Kubernetes API /api/v1 unauth - anonymous read of the API surface",
         r'"kind"\s*:\s*"APIResourceList"'),
    "/metrics":
        ("Prometheus /metrics unauth - internal counters, sometimes secrets",
         r"(?m)^#\s*(?:HELP|TYPE)\s"),
    # Docker daemon exposed on TCP - full host takeover.
    "/version":
        ("Docker Engine /version - if this is a Docker socket over TCP, full RCE",
         r'"ApiVersion"\s*:\s*"[0-9.]+".*"Os"'),
    "/containers/json":
        ("Docker Engine /containers/json - unauth container listing == RCE via docker run",
         r'"Id"\s*:\s*"[0-9a-f]{12,}"'),
    # Consul / Nomad / Vault.
    "/v1/agent/self":
        ("Consul /v1/agent/self unauth - agent config leak",
         r'"Config"\s*:\s*\{'),
    "/v1/sys/health":
        ("HashiCorp Vault sys/health unauth - Vault reachable",
         r'"initialized"|"sealed"'),
    # Jenkins, GitLab, generic dashboards.
    "/api/json":
        ("Jenkins /api/json unauth - job listing (jobs/users leak, sometimes anon build)",
         r'"jobs"\s*:\s*\['),
    "/whoami":
        ("Traefik /whoami / other whoami endpoints - leak headers/internals",
         r"Hostname:|X-Forwarded"),
    # Cisco / Fortinet / firewall management (usually redirects unless open).
    "/global-protect/login.esp":
        ("PAN GlobalProtect portal reachable - version + CVE surface",
         r"GlobalProtect|Palo Alto"),
    # Kubernetes kubelet read-only port (10255) - deprecated but still seen.
    "/pods":
        ("Kubelet /pods unauth - pod listing, secrets in env",
         r'"kind"\s*:\s*"PodList"'),
    # Generic Swagger / OpenAPI - exposed schema is not a vuln by itself, but a
    # green light to test each endpoint for auth bypass.
    "/swagger-ui/":
        ("Swagger UI exposed - full API surface listed, test each endpoint",
         r"swagger-ui|Swagger UI"),
    "/openapi.json":
        ("OpenAPI schema exposed - inventory every route to test for auth bypass",
         r'"openapi"\s*:\s*"[0-9.]+"'),
    "/api-docs":
        ("Swagger /api-docs exposed - inventory every route",
         r'"swagger"|"openapi"'),
}


def probe_commands(base_url: str) -> list[str]:
    """Ready `curl -w %{http_code}` probes for every unauth-management path."""
    base = base_url.rstrip("/")
    return [
        f"curl -s -o /tmp/bl_body -w '%{{http_code}} {p}\\n' {base}{p} && "
        f"echo '---BODY---'; head -c 400 /tmp/bl_body; echo"
        for p in UNAUTH_PATHS
    ]


_STATUS_LINE_RE = re.compile(r"^(\d{3})\s+(\S+)")


def classify_probes(probe_output: str, base_url: str) -> list[Finding]:
    """Turn the batched probe transcript into findings.

    Splits on the ``---BODY---`` marker each probe prints, then for each (status,
    path, body) tuple checks the curated evidence regex. Confirmed = real content
    matched; suspected = 200/401/403 without a marker match (still worth a look).
    """
    out: list[Finding] = []
    host = _host(base_url)
    # Split into per-probe chunks: each chunk begins with "CODE PATH" and ends
    # before the next such line.
    chunks: list[str] = []
    cur: list[str] = []
    for line in (probe_output or "").splitlines():
        if _STATUS_LINE_RE.match(line):
            if cur:
                chunks.append("\n".join(cur))
            cur = [line]
        else:
            cur.append(line)
    if cur:
        chunks.append("\n".join(cur))

    for chunk in chunks:
        m = _STATUS_LINE_RE.match(chunk.splitlines()[0])
        if not m:
            continue
        code, path = int(m.group(1)), m.group(2)
        entry = UNAUTH_PATHS.get(path)
        if not entry:
            continue
        note, marker = entry
        body = chunk.split("---BODY---", 1)[1] if "---BODY---" in chunk else ""
        confirmed = code in (200, 206) and bool(re.search(marker, body, re.S))
        if confirmed:
            out.append(Finding(
                title=f"Unauthenticated management endpoint: {path}",
                severity=Severity.HIGH, host=host,
                description=f"{base_url.rstrip('/')}{path} returned {code} with "
                            f"content matching the expected data marker - {note}.",
                evidence=f"HTTP {code} {path}\n{body[:400]}",
                validation="confirmed", proof=f"marker matched at {path}",
                remediation="Require authentication on management endpoints, or "
                            "restrict them to a management network."))
        elif code in (200, 401, 403):
            out.append(Finding(
                title=f"Management endpoint present: {path}",
                severity=Severity.INFO, host=host,
                description=f"{base_url.rstrip('/')}{path} returned {code} - {note}. "
                            "Probe the surrounding API for auth bypass or defaults.",
                evidence=f"HTTP {code} {path}"))
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url
