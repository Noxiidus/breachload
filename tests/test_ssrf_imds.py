"""Generalized SSRF -> cloud IMDS credential extraction."""

from breachload.analysis.ssrf_imds import imds_probes, parse_imds


class TestProbes:
    def test_covers_the_big_three(self):
        probes = dict(imds_probes())
        assert "aws-imdsv1" in probes
        assert "gcp" in probes and "Metadata-Flavor:Google" in probes["gcp"]
        assert "azure" in probes and "Metadata:true" in probes["azure"]


class TestParseImds:
    def test_aws_creds_extracted(self):
        body = ('{"Code":"Success","AccessKeyId":"ASIAIOSFODNN7EXAMPLE",'
                '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
                '"Token":"AAAA1234BBBB5678"}')
        f, c = parse_imds(body, host="1.2.3.4")
        assert f and "AWS instance credentials" in f[0].title
        assert f[0].severity.value == "critical"
        secrets = {cr.username: cr.secret for cr in c}
        assert secrets["AWS_ACCESS_KEY_ID"].startswith("ASIA")
        assert secrets["AWS_SECRET_ACCESS_KEY"].endswith("KEY")

    def test_gcp_token(self):
        body = '{"access_token":"ya29.abc123def456","expires_in":3600,"token_type":"Bearer"}'
        f, c = parse_imds(body)
        assert f and "GCP" in f[0].title
        assert c and c[0].source.endswith("(GCP)")

    def test_azure_jwt(self):
        body = '{"access_token":"eyJhbGciOi.eyJhdWQiOi.abcdef","token_type":"Bearer"}'
        f, c = parse_imds(body)
        assert f and "Azure" in f[0].title
        assert c and c[0].kind == "token"

    def test_generic_json_noted(self):
        body = '{"unknown":"metadata","instance":"foo"}'
        f, _ = parse_imds(body)
        assert f and "IMDS-shaped JSON" in f[0].title
        assert f[0].severity.value == "medium"

    def test_junk_returns_nothing(self):
        assert parse_imds("<html>404</html>") == ([], [])

    def test_empty(self):
        assert parse_imds("") == ([], [])
