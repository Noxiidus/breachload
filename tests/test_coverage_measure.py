"""Held-out coverage measurement primitives (the module, not the eval)."""

from breachload.analysis.coverage import (
    BoxExpectation,
    _state_haystack,
    measure,
    summarize,
)
from breachload.core.state import (
    Credential,
    EngagementState,
    Finding,
    Service,
    Severity,
)


def _state():
    st = EngagementState(name="test")
    h = st.upsert_host("10.10.11.5")
    h.tags += ["dc", "domain:corp.local"]
    h.upsert_service(Service(port=80, name="http", notes=["webapp: Apache NiFi 1.21"]))
    st.add_finding(Finding(title="AS-REP roastable account: guest",
                           severity=Severity.HIGH))
    st.add_finding(Finding(title="ADCS ESC1 on template UserCert",
                           severity=Severity.CRITICAL))
    st.credentials.append(Credential(username="bob", secret="pw",
                                     kind="password"))
    return st


class TestHaystack:
    def test_covers_all_state_surfaces(self):
        hay = _state_haystack(_state())
        for tok in ("10.10.11.5", "dc", "corp.local", "nifi", "as-rep",
                    "esc1", "bob"):
            assert tok in hay


class TestMeasure:
    def test_all_hit(self):
        exp = BoxExpectation("t", "easy", "kerberoast/asrep",
                             ["as-rep", "dc", "corp.local"])
        r = measure(_state(), exp)
        assert r.passed and r.score == 1.0
        assert not r.missed_tokens

    def test_partial_hit_still_passes(self):
        exp = BoxExpectation("t", "easy", "adcs", ["esc1", "yubikey-magic"])
        r = measure(_state(), exp)
        assert r.passed and 0 < r.score < 1

    def test_no_hits_fails(self):
        exp = BoxExpectation("t", "easy", "obscure",
                             ["completely-not-there", "also-missing"])
        r = measure(_state(), exp)
        assert not r.passed and r.score == 0.0

    def test_case_insensitive(self):
        exp = BoxExpectation("t", "easy", "case", ["NIFI", "DC"])
        assert measure(_state(), exp).score == 1.0


class TestSummarize:
    def test_aggregates_by_difficulty_and_class(self):
        results = [
            measure(_state(), BoxExpectation("a", "easy", "kerberoast", ["dc"])),
            measure(_state(), BoxExpectation("b", "easy", "kerberoast", ["missing"])),
            measure(_state(), BoxExpectation("c", "medium", "webapp", ["nifi"])),
        ]
        s = summarize(results)
        assert s["total"] == 3 and s["passed"] == 2
        assert s["by_difficulty"]["easy"] == 50.0
        assert s["by_difficulty"]["medium"] == 100.0
        assert s["by_class"]["kerberoast"] == 50.0

    def test_empty(self):
        s = summarize([])
        assert s == {"total": 0, "passed": 0, "overall_pass_rate": 0.0,
                     "by_difficulty": {}, "by_class": {}, "avg_score": 0.0}
