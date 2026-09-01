"""Generalized cloud-service post-exploitation commands.

Given AWS / GCP / Azure credentials (from IMDS via ssrf_imds, from a compromised
config file, or handed in manually), emit the ready enumeration commands per
provider. This is the class-level bridge from "we got a token" to "here is what
to check first". Pure argv builders - the operator runs them.
"""

from __future__ import annotations

from ..core.state import Credential, EngagementState

AWS_ENUM_COMMANDS: list[tuple[str, list[str]]] = [
    ("identity",
     ["aws", "sts", "get-caller-identity"]),
    ("iam-user (privileges)",
     ["aws", "iam", "get-user"]),
    ("iam-attached-user-policies",
     ["aws", "iam", "list-attached-user-policies", "--user-name", "<user>"]),
    ("s3 buckets (read-any-bucket check)",
     ["aws", "s3api", "list-buckets"]),
    ("ec2 instances (all regions)",
     ["aws", "ec2", "describe-instances", "--region", "<region>"]),
    ("lambda functions (env vars often leak secrets)",
     ["aws", "lambda", "list-functions", "--region", "<region>"]),
    ("secretsmanager secrets",
     ["aws", "secretsmanager", "list-secrets", "--region", "<region>"]),
    ("ssm parameters",
     ["aws", "ssm", "describe-parameters", "--region", "<region>"]),
    ("rds instances",
     ["aws", "rds", "describe-db-instances", "--region", "<region>"]),
    ("assume-role hunt (pacu / iam:ListRoles first)",
     ["aws", "iam", "list-roles"]),
]

GCP_ENUM_COMMANDS: list[tuple[str, list[str]]] = [
    ("identity",
     ["gcloud", "auth", "list"]),
    ("current project",
     ["gcloud", "config", "list", "project"]),
    ("iam roles for current identity",
     ["gcloud", "projects", "get-iam-policy", "<project>"]),
    ("storage buckets",
     ["gsutil", "ls"]),
    ("compute instances",
     ["gcloud", "compute", "instances", "list"]),
    ("cloud functions (env leaks)",
     ["gcloud", "functions", "list"]),
    ("secretmanager secrets",
     ["gcloud", "secrets", "list"]),
    ("service accounts + keys",
     ["gcloud", "iam", "service-accounts", "list"]),
]

AZURE_ENUM_COMMANDS: list[tuple[str, list[str]]] = [
    ("identity",
     ["az", "account", "show"]),
    ("subscriptions",
     ["az", "account", "list"]),
    ("resource groups",
     ["az", "group", "list"]),
    ("keyvaults + secrets",
     ["az", "keyvault", "list"]),
    ("storage accounts",
     ["az", "storage", "account", "list"]),
    ("vms",
     ["az", "vm", "list"]),
    ("managed identities",
     ["az", "identity", "list"]),
    ("role assignments",
     ["az", "role", "assignment", "list"]),
]

_PROVIDER_MAP = {
    "aws": AWS_ENUM_COMMANDS,
    "gcp": GCP_ENUM_COMMANDS,
    "azure": AZURE_ENUM_COMMANDS,
}


def enum_commands(provider: str) -> list[tuple[str, list[str]]]:
    """Ordered (label, argv) enumeration commands for a provider."""
    return _PROVIDER_MAP.get(provider.lower(), [])


def _cloud_creds_in_state(state: EngagementState) -> dict[str, list[Credential]]:
    """Group state's cloud credentials by provider (looking at source/username)."""
    buckets: dict[str, list[Credential]] = {"aws": [], "gcp": [], "azure": []}
    for c in state.credentials:
        src = (c.source or "").lower()
        user = (c.username or "").lower()
        if "aws" in src or user.startswith("aws_"):
            buckets["aws"].append(c)
        elif "gcp" in src or "google" in src or user.startswith("gcp"):
            buckets["gcp"].append(c)
        elif "azure" in src or "az " in src:
            buckets["azure"].append(c)
    return buckets


def commands_for_state(state: EngagementState) -> list[tuple[str, str, list[str]]]:
    """(provider, label, argv) for every provider we hold a credential for."""
    out: list[tuple[str, str, list[str]]] = []
    for provider, creds in _cloud_creds_in_state(state).items():
        if not creds:
            continue
        for label, argv in enum_commands(provider):
            out.append((provider, label, argv))
    return out
