"""NVD 2.0 feed import into the KB schema."""

import json

from breachload.analysis.cve import CveMatcher
from breachload.analysis.nvd import parse_nvd
from breachload.core.state import EngagementState, Service


def _cve(cve_id, product, severity="HIGH", start=None, end_excl=None, desc="An issue."):
    cpe = {"criteria": f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*"}
    if start:
        cpe["versionStartIncluding"] = start
    if end_excl:
        cpe["versionEndExcluding"] = end_excl
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": severity}}]},
        "configurations": [{"nodes": [{"cpeMatch": [cpe]}]}],
    }}


class TestParseNvd:
    def test_extracts_entry_with_range(self):
        data = {"vulnerabilities": [
            _cve("CVE-2024-6387", "openssh", "HIGH", start="8.5", end_excl="9.8")
        ]}
        entries = parse_nvd(data)
        assert entries == [{
            "match": ["openssh"], "range": ">=8.5,<9.8",
            "cve": "CVE-2024-6387", "severity": "high", "name": "An issue.",
        }]

    def test_skips_cve_without_version_range(self):
        data = {"vulnerabilities": [_cve("CVE-0000-0001", "openssh")]}  # no start/end
        assert parse_nvd(data) == []

    def test_severity_mapping_and_product_underscore(self):
        data = {"vulnerabilities": [
            _cve("CVE-1", "http_server", "CRITICAL", start="2.4.49", end_excl="2.4.51")
        ]}
        entry = parse_nvd(data)[0]
        assert entry["severity"] == "critical"
        assert entry["match"] == ["http server"]     # underscores become spaces

    def test_long_description_is_truncated(self):
        data = {"vulnerabilities": [
            _cve("CVE-2", "x", start="1", end_excl="2", desc="word " * 50)
        ]}
        name = parse_nvd(data)[0]["name"]
        assert name.endswith("...")           # ASCII ellipsis (cp1250-safe console)
        assert name.isascii()

    def test_imported_entry_is_matchable(self):
        # An imported entry must actually fire in the matcher.
        data = {"vulnerabilities": [
            _cve("CVE-2024-6387", "openssh", "HIGH", start="8.5", end_excl="9.8")
        ]}
        matcher = CveMatcher(CveMatcher._parse({"entries": parse_nvd(data)}))
        st = EngagementState(name="t")
        st.upsert_host("10.0.0.1").upsert_service(
            Service(port=22, name="ssh", product="OpenSSH", version="9.0"))
        assert any("CVE-2024-6387" in f.cve for f in matcher.findings_for(st))


class TestKbEnvExtension:
    def test_default_merges_breachload_kb(self, tmp_path, monkeypatch):
        extra = tmp_path / "extra.json"
        extra.write_text(json.dumps({"entries": [
            {"match": ["acmed"], "range": "==1.0", "cve": "CVE-9999-1",
             "severity": "high", "name": "ACME daemon RCE"}
        ]}), encoding="utf-8")
        monkeypatch.setenv("BREACHLOAD_KB", str(extra))
        matcher = CveMatcher.default()
        assert any(e.cve == "CVE-9999-1" for e in matcher.entries)
        # Bundled entries are still present too.
        assert any(e.cve == "CVE-2021-41773" for e in matcher.entries)
