"""Generalized secret scanning + sensitive-content discovery."""

from breachload.analysis.secretscan import (
    content_discovery_commands,
    parse_content_discovery,
    scan_secrets,
)


class TestScanSecrets:
    def test_aws_key(self):
        f, c = scan_secrets("id=AKIAIOSFODNN7EXAMPLE more")
        assert any("AWS access key" in x.title for x in f)
        assert any(cr.secret.startswith("AKIA") for cr in c)

    def test_private_key(self):
        f, _ = scan_secrets("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
        assert any("Private key" in x.title for x in f)

    def test_db_uri_becomes_credential(self):
        f, c = scan_secrets("DATABASE_URL=postgres://bob:s3cr3t@db.local:5432/app")
        assert any("DB connection URI" in x.title for x in f)
        assert any("bob:s3cr3t" in (cr.secret or "") for cr in c)

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abcDEF123456"
        f, _ = scan_secrets(jwt)
        assert any("JWT" in x.title for x in f)

    def test_password_assignment(self):
        f, c = scan_secrets('db_password = "Winter2025!"')
        assert any("Password assignment" in x.title for x in f)
        assert any(cr.secret == "Winter2025!" for cr in c)

    def test_placeholder_ignored(self):
        f, _ = scan_secrets('password = "changeme"')
        assert not f

    def test_confirmed_validation(self):
        f, _ = scan_secrets("ghp_" + "a" * 36)
        assert f and f[0].validation == "confirmed"

    def test_dedup(self):
        f, _ = scan_secrets("AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE")
        assert len([x for x in f if "AWS access key" in x.title]) == 1

    def test_clean_text_no_findings(self):
        f, c = scan_secrets("just some normal text with no secrets")
        assert not f and not c


class TestContentDiscovery:
    def test_commands_cover_git_and_env(self):
        cmds = content_discovery_commands("http://x/")
        joined = "\n".join(cmds)
        assert "/.git/HEAD" in joined and "/.env" in joined and "git-dumper" in joined

    def test_parse_hit_200_is_high_confirmed(self):
        out = "200 /.env\n404 /nope\n200 /.git/HEAD"
        f = parse_content_discovery(out, "http://x/")
        titles = [x.title for x in f]
        assert any("/.env" in t for t in titles)
        env = next(x for x in f if "/.env" in x.title)
        assert env.severity.value == "high" and env.validation == "confirmed"

    def test_parse_403_is_info_suspected(self):
        f = parse_content_discovery("403 /.git/config", "http://x/")
        assert f and f[0].severity.value == "info" and f[0].validation == "suspected"

    def test_parse_unknown_path_ignored(self):
        assert parse_content_discovery("200 /random/thing", "http://x/") == []
