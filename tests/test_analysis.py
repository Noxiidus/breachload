"""Analysis layer: CVE version matching, correlation rules, analyzer dedup."""

from breachload.analysis.analyzer import Analyzer
from breachload.analysis.correlator import Correlator
from breachload.analysis.cve import CveMatcher, satisfies
from breachload.core.state import EngagementState, Service, Severity


class TestVersionConstraints:
    def test_exact(self):
        assert satisfies("2.4.49", "==2.4.49")
        assert not satisfies("2.4.50", "==2.4.49")

    def test_range(self):
        assert satisfies("4.6.0", ">=3.5.0,<4.6.4")
        assert not satisfies("4.6.4", ">=3.5.0,<4.6.4")
        assert not satisfies("3.4.0", ">=3.5.0,<4.6.4")

    def test_less_than(self):
        assert satisfies("7.2", "<7.7")
        assert not satisfies("8.0", "<7.7")

    def test_empty_version_never_matches(self):
        assert not satisfies("", "==1.0")

    def test_uneven_component_counts(self):
        assert satisfies("2.4", "<2.4.50")     # 2.4 == 2.4.0 < 2.4.50
        assert satisfies("1.4.0", "<=1.4.0")


class TestCveMatcher:
    def _state(self, product, version, name="http") -> EngagementState:
        st = EngagementState(name="t")
        host = st.upsert_host("10.10.10.5")
        host.upsert_service(Service(port=80, name=name, product=product, version=version))
        return st

    def test_matches_known_cve(self):
        findings = CveMatcher.default().findings_for(self._state("Apache httpd", "2.4.49"))
        assert any("CVE-2021-41773" in f.cve for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_patched_version_no_match(self):
        findings = CveMatcher.default().findings_for(self._state("Apache httpd", "2.4.58"))
        assert not any("CVE-2021-41773" in f.cve for f in findings)

    def test_no_version_no_match(self):
        st = self._state("Apache httpd", None)
        assert CveMatcher.default().findings_for(st) == []

    def test_product_must_match(self):
        findings = CveMatcher.default().findings_for(self._state("nginx", "2.4.49"))
        assert not any("CVE-2021-41773" in f.cve for f in findings)

    def test_every_kb_entry_is_reachable(self):
        # Guards against dead KB entries: for each entry, build a service whose
        # product carries all match tokens and whose version satisfies the range,
        # then assert the CVE actually fires. Catches unmatchable tokens and
        # version ranges that the comparator cannot represent.
        matcher = CveMatcher.default()
        for entry in matcher.entries:
            version = _satisfying_version(entry.range)
            assert satisfies(version, entry.range), \
                f"{entry.cve}: no representable version satisfies {entry.range!r}"
            product = " ".join(entry.match)
            state = self._state(product, version, name="svc")
            cves = [c for f in matcher.findings_for(state) for c in f.cve]
            assert entry.cve in cves, f"{entry.cve} unreachable via product={product!r} v={version}"


def _satisfying_version(spec: str) -> str:
    """Derive a version that satisfies `spec` (for constraints used in the KB)."""
    lower = None
    for part in spec.split(","):
        op = part[:2] if part[:2] in ("==", ">=", "<=") else part[:1]
        ref = part[len(op):].strip()
        if op in ("==", ">="):
            lower = ref
    return lower or "0.0.1"   # no lower bound (only < / <=): a tiny version works


class TestCorrelator:
    def _host_state(self, os_guess, services) -> EngagementState:
        st = EngagementState(name="t")
        host = st.upsert_host("10.10.10.5")
        host.os_guess = os_guess
        for svc in services:
            host.upsert_service(svc)
        return st

    def test_eternalblue_candidate(self):
        st = self._host_state("Windows 7", [Service(port=445, name="microsoft-ds")])
        findings = Correlator().findings_for(st)
        assert any("MS17-010" in f.title and f.severity == Severity.HIGH for f in findings)

    def test_no_candidate_on_modern_windows(self):
        st = self._host_state("Windows Server 2019", [Service(port=445, name="microsoft-ds")])
        assert not any("MS17-010" in f.title for f in Correlator().findings_for(st))

    def test_no_candidate_without_smb(self):
        st = self._host_state("Windows 7", [Service(port=80, name="http")])
        assert not any("MS17-010" in f.title for f in Correlator().findings_for(st))

    def test_bare_seven_in_build_number_is_not_legacy(self):
        # "7" inside a build number must not be read as "Windows 7".
        st = self._host_state("Windows (build 17763)",
                              [Service(port=445, name="microsoft-ds")])
        assert not any("MS17-010" in f.title for f in Correlator().findings_for(st))

    def test_server_2008_still_matches(self):
        st = self._host_state("Windows Server 2008 R2",
                              [Service(port=445, name="microsoft-ds")])
        assert any("MS17-010" in f.title for f in Correlator().findings_for(st))

    def test_cleartext_ftp(self):
        st = self._host_state(None, [Service(port=21, name="ftp")])
        titles = [f.title for f in Correlator().findings_for(st)]
        assert any("Cleartext FTP" in t for t in titles)

    def test_anonymous_ftp(self):
        svc = Service(port=21, name="ftp")
        svc.notes.append("Anonymous login allowed")
        st = self._host_state(None, [svc])
        titles = [f.title for f in Correlator().findings_for(st)]
        assert any("Anonymous FTP" in t for t in titles)


class TestAnalyzerDedup:
    def _vuln_state(self) -> EngagementState:
        st = EngagementState(name="t")
        host = st.upsert_host("10.10.10.5")
        host.os_guess = "Windows 7"
        host.upsert_service(Service(port=80, name="http", product="Apache httpd", version="2.4.49"))
        host.upsert_service(Service(port=445, name="microsoft-ds"))
        return st

    def test_adds_findings_once(self):
        analyzer = Analyzer.default()
        st = self._vuln_state()
        first = analyzer.analyze(st)
        assert len(first) >= 2  # CVE + EternalBlue candidate
        before = len(st.findings)
        second = analyzer.analyze(st)
        assert second == []                 # idempotent
        assert len(st.findings) == before   # no duplicates
