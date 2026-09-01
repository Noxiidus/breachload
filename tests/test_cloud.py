"""Cloud enumeration command library."""

from breachload.analysis.cloud import commands_for_state, enum_commands
from breachload.core.state import Credential, EngagementState


class TestEnumCommands:
    def test_aws_covers_identity_iam_s3_lambda(self):
        cmds = [c[0] for c in enum_commands("aws")]
        for tok in ("identity", "iam", "s3", "lambda", "secretsmanager", "ssm"):
            assert any(tok in c for c in cmds)

    def test_gcp_covers_identity_storage_functions(self):
        cmds = [c[0] for c in enum_commands("gcp")]
        for tok in ("identity", "storage", "functions", "secret"):
            assert any(tok in c for c in cmds)

    def test_azure_covers_identity_keyvault_vms(self):
        cmds = [c[0] for c in enum_commands("azure")]
        for tok in ("identity", "keyvault", "vms"):
            assert any(tok in c for c in cmds)

    def test_unknown_provider(self):
        assert enum_commands("nope") == []

    def test_argv_uses_provider_cli(self):
        assert enum_commands("aws")[0][1][0] == "aws"
        assert enum_commands("gcp")[0][1][0] == "gcloud"
        assert enum_commands("azure")[0][1][0] == "az"


class TestCommandsForState:
    def test_returns_aws_when_aws_cred_present(self):
        st = EngagementState(name="t")
        st.credentials.append(Credential(
            username="AWS_ACCESS_KEY_ID", secret="AKIA000",
            kind="token", source="SSRF/IMDS (AWS)"))
        rows = commands_for_state(st)
        assert rows and all(prov == "aws" for prov, _l, _a in rows)

    def test_multi_provider(self):
        st = EngagementState(name="t")
        st.credentials.append(Credential(username="AWS_ACCESS_KEY_ID",
                                         secret="x", source="SSRF/IMDS (AWS)"))
        st.credentials.append(Credential(username="gcp-metadata",
                                         secret="ya29.x", source="SSRF/IMDS (GCP)"))
        rows = commands_for_state(st)
        provs = {p for p, _l, _a in rows}
        assert {"aws", "gcp"}.issubset(provs)

    def test_no_cloud_creds_no_rows(self):
        st = EngagementState(name="t")
        st.credentials.append(Credential(username="bob", secret="pw",
                                         kind="password"))
        assert commands_for_state(st) == []
