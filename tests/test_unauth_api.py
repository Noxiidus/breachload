"""Generalized unauthenticated admin/API detector."""

from breachload.analysis.unauth_api import (
    UNAUTH_PATHS,
    classify_probes,
    probe_commands,
)


class TestProbeCommands:
    def test_covers_the_class(self):
        cmds = "\n".join(probe_commands("http://target/"))
        for p in ("/nifi-api/access/config", "/actuator/env",
                  "/_cluster/health", "/api/v1", "/containers/json", "/openapi.json"):
            assert p in cmds

    def test_argv_safe_curls(self):
        # Every probe is a single-shot curl string, no shell-metachar surprises
        # beyond the ones curl itself needs; the CLI prints them verbatim for
        # the operator to review-then-run.
        cmds = probe_commands("http://target/")
        assert all(c.startswith("curl ") for c in cmds)


class TestClassifyProbes:
    def _tx(self, code, path, body):
        return f"{code} {path}\n---BODY---\n{body}\n"

    def test_nifi_supports_login_false_is_confirmed_high(self):
        tx = self._tx(200, "/nifi-api/access/config",
                      '{"config":{"supportsLogin":false}}')
        findings = classify_probes(tx, "http://flow.helix.htb/")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity.value == "high" and f.validation == "confirmed"
        assert "supportsLogin" in f.evidence

    def test_actuator_env_confirmed(self):
        tx = self._tx(200, "/actuator/env",
                      '{"activeProfiles":[],"propertySources":[]}')
        f = classify_probes(tx, "http://app/")
        assert f and f[0].validation == "confirmed"

    def test_present_but_no_marker_is_info_suspected(self):
        # 200 without a data marker -> generic /openapi.json returned HTML index
        tx = self._tx(200, "/openapi.json", "<html>not a schema</html>")
        f = classify_probes(tx, "http://app/")
        assert f and f[0].severity.value == "info" and f[0].validation == "suspected"

    def test_403_is_present_suspected(self):
        tx = self._tx(403, "/actuator", "Forbidden")
        f = classify_probes(tx, "http://app/")
        assert f and f[0].severity.value == "info"

    def test_404_is_ignored(self):
        tx = self._tx(404, "/actuator/env", "not found")
        assert classify_probes(tx, "http://app/") == []

    def test_unknown_path_ignored(self):
        tx = self._tx(200, "/random/path", "hi")
        assert classify_probes(tx, "http://app/") == []

    def test_multiple_probes_in_one_transcript(self):
        tx = (self._tx(200, "/nifi-api/access/config",
                       '{"config":{"supportsLogin":false}}')
              + self._tx(404, "/actuator/env", "no")
              + self._tx(200, "/_cluster/health",
                         '{"cluster_name":"prod","status":"green"}'))
        findings = classify_probes(tx, "http://app/")
        titles = [f.title for f in findings]
        assert any("nifi-api" in t for t in titles)
        assert any("_cluster/health" in t for t in titles)
        assert not any("actuator/env" in t for t in titles)

    def test_confirmed_findings_carry_remediation(self):
        tx = self._tx(200, "/nifi-api/access/config",
                      '{"config":{"supportsLogin":false}}')
        f = classify_probes(tx, "http://app/")
        assert f[0].remediation


class TestClassCoverage:
    def test_class_carries_nifi_spring_es_k8s_docker(self):
        # Sanity: the class table covers the exemplars the module claims.
        paths = set(UNAUTH_PATHS)
        assert "/nifi-api/access/config" in paths
        assert "/actuator/env" in paths
        assert "/_cluster/health" in paths
        assert "/containers/json" in paths
        assert "/api/v1" in paths
