"""Tamper-evident audit log — hash chain + verification."""

import json

from breachload.core.state import Finding, Severity
from breachload.report.scoring import band_for, score_label
from breachload.safety.audit import AuditLog, verify_chain


class TestHashChain:
    def test_intact_chain_verifies(self, tmp_path):
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(5):
            log.write("action", n=i)
        res = verify_chain(tmp_path / "audit.jsonl")
        assert res.ok and res.records == 5

    def test_each_record_links_to_previous(self, tmp_path):
        p = tmp_path / "audit.jsonl"
        log = AuditLog(p)
        log.write("a")
        log.write("b")
        lines = [json.loads(x) for x in p.read_text().splitlines()]
        assert lines[1]["prev"] == lines[0]["hash"]

    def test_edit_breaks_chain(self, tmp_path):
        p = tmp_path / "audit.jsonl"
        log = AuditLog(p)
        log.write("action", n=0)
        log.write("action", n=1)
        log.write("action", n=2)
        # Tamper with the middle record's content.
        lines = p.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["n"] = 999
        lines[1] = json.dumps(rec)
        p.write_text("\n".join(lines) + "\n")
        res = verify_chain(p)
        assert not res.ok and res.broken_at == 2

    def test_delete_breaks_chain(self, tmp_path):
        p = tmp_path / "audit.jsonl"
        log = AuditLog(p)
        log.write("a")
        log.write("b")
        log.write("c")
        lines = p.read_text().splitlines()
        del lines[1]                       # remove the middle record
        p.write_text("\n".join(lines) + "\n")
        res = verify_chain(p)
        assert not res.ok

    def test_empty_log_is_ok(self, tmp_path):
        res = verify_chain(tmp_path / "nope.jsonl")
        assert res.ok and res.records == 0

    def test_write_still_records_fields(self, tmp_path):
        p = tmp_path / "audit.jsonl"
        AuditLog(p).write("scope_block", target="evil.com", reason="off-scope")
        rec = json.loads(p.read_text().splitlines()[0])
        assert rec["event"] == "scope_block" and rec["target"] == "evil.com"
        assert "hash" in rec and "prev" in rec


class TestScoring:
    def test_real_cvss_shown(self):
        f = Finding(title="x", severity=Severity.HIGH, cvss=9.8)
        assert score_label(f) == "9.8"

    def test_band_fallback(self):
        f = Finding(title="x", severity=Severity.CRITICAL)
        assert "Critical" in score_label(f)

    def test_band_for(self):
        assert "High" in band_for(Severity.HIGH)
