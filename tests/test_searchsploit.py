"""searchsploit (Exploit-DB) integration."""

from breachload.analysis.searchsploit import parse_json, run_search, search_terms
from breachload.core.state import EngagementState, Service

_JSON = """{
  "RESULTS_EXPLOIT": [
    {"Title": "Apache 2.4.49 - Path Traversal & Remote Code Execution",
     "EDB-ID": "50383", "Path": "/x/50383.sh", "Codes": "CVE-2021-41773"},
    {"Title": "Apache 2.4 - Denial of Service", "EDB-ID": "12345", "Path": "", "Codes": ""}
  ],
  "RESULTS_SHELLCODE": []
}"""


class TestSearchTerms:
    def test_strips_noise_and_keeps_major_version(self):
        svc = Service(port=80, product="Apache httpd", version="2.4.49")
        assert search_terms(svc) == "apache 2.4"

    def test_none_without_product(self):
        assert search_terms(Service(port=80, version="1.0")) is None


class TestParseJson:
    def test_extracts_hits_and_cves(self):
        hits = parse_json(_JSON)
        assert len(hits) == 2
        assert hits[0].edb_id == "50383" and hits[0].cves == ["CVE-2021-41773"]

    def test_bad_json(self):
        assert parse_json("not json") == []


class TestRunSearch:
    def test_findings_from_injected_runner(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.5").upsert_service(
            Service(port=80, name="http", product="Apache httpd", version="2.4.49"))
        findings = run_search(st, runner=lambda argv: _JSON)
        assert len(findings) == 1
        f = findings[0]
        assert "Exploit-DB matches" in f.title
        assert f.severity.value == "high"          # an RCE title present
        assert "searchsploit -m 50383" in f.exploit
        assert "CVE-2021-41773" in f.cve

    def test_skips_services_without_product(self):
        st = EngagementState(name="t")
        st.upsert_host("10.10.10.5").upsert_service(Service(port=22, name="ssh"))
        assert run_search(st, runner=lambda argv: _JSON) == []

    def test_dedupes_identical_queries(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.5")
        h.upsert_service(Service(port=80, name="http", product="Apache", version="2.4"))
        h.upsert_service(Service(port=8080, name="http", product="Apache", version="2.4"))
        calls = []

        def runner(argv):
            calls.append(argv)
            return _JSON

        run_search(st, runner=runner)
        assert len(calls) == 1                      # same "apache 2.4" query issued once
