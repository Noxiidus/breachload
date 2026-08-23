"""Tier 3: ranged fingerprint, IMDS credential parse, dangling ADCS templates."""

from breachload.analysis.adcs import parse_dangling_templates
from breachload.analysis.postexploit import loot, parse_cloud_creds
from breachload.core.netprobe import ranged_fingerprint


class TestRangedFingerprint:
    def test_extracts_server_and_title(self):
        raw = ("HTTP/1.1 206 Partial Content\r\n"
               "Server: nginx/1.25.3\r\n"
               "X-Powered-By: PHP/8.2\r\n\r\n"
               "<html><head><title>Admin Panel</title></head>")

        fp = ranged_fingerprint("10.10.10.9", runner=lambda argv: raw)
        assert fp.get("Server") == "nginx/1.25.3"
        assert fp.get("X-Powered-By") == "PHP/8.2"
        assert fp.get("Title") == "Admin Panel"

    def test_empty_on_nothing(self):
        assert ranged_fingerprint("10.10.10.9", runner=lambda argv: "") == {}


class TestCloudCreds:
    def test_aws_imds_json(self):
        text = """{
          "AccessKeyId" : "ASIAIOSFODNN7EXAMPLE",
          "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          "Token" : "%s"
        }""" % ("A" * 120)
        creds = parse_cloud_creds(text)
        assert any(c.username.startswith("ASIA") and c.kind == "token" for c in creds)
        assert any("session-token" in (c.username or "") for c in creds)

    def test_aws_env(self):
        text = ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
        creds = parse_cloud_creds(text)
        assert len(creds) == 1 and creds[0].username == "AKIAIOSFODNN7EXAMPLE"

    def test_wired_into_loot(self):
        text = ('"AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
                '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
        _findings, creds = loot(text)
        assert any(c.kind == "token" for c in creds)

    def test_no_false_positive(self):
        assert parse_cloud_creds("just some regular text here") == []


class TestDanglingTemplates:
    def test_flags_enabled_but_undefined(self):
        text = """
Certificate Authorities
  0
    CA Name : corp-CA
    Enabled Certificate Templates : ['User', 'Machine', 'GhostTemplate']
Certificate Templates
  0
    Template Name : User
  1
    Template Name : Machine
"""
        findings = parse_dangling_templates(text)
        titles = [f.title for f in findings]
        assert any("GhostTemplate" in t for t in titles)
        assert not any("User" in t or "Machine" in t for t in titles)

    def test_no_dangling_when_all_defined(self):
        text = ("Enabled Certificate Templates : ['User']\n"
                "Certificate Templates\n    Template Name : User\n")
        assert parse_dangling_templates(text) == []
