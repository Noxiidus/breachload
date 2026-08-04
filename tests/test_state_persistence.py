"""State persistence — atomic, crash-safe save/load."""

from breachload.core.state import EngagementState, Finding, Service, Severity


class TestPersistence:
    def test_save_load_roundtrip(self, tmp_path):
        st = EngagementState(name="t")
        st.upsert_host("10.0.0.1").upsert_service(Service(port=80, name="http"))
        st.add_finding(Finding(title="x", severity=Severity.HIGH))
        p = tmp_path / "state.json"
        st.save(p)
        loaded = EngagementState.load(p)
        assert loaded.name == "t" and "10.0.0.1" in loaded.hosts
        assert loaded.findings[0].title == "x"

    def test_save_leaves_no_tmp_file(self, tmp_path):
        p = tmp_path / "state.json"
        EngagementState(name="t").save(p)
        assert p.exists()
        assert not (tmp_path / "state.json.tmp").exists()

    def test_save_over_stale_tmp_succeeds(self, tmp_path):
        # A leftover .tmp from a previous crash must not block a fresh save.
        p = tmp_path / "state.json"
        (tmp_path / "state.json.tmp").write_text("garbage", encoding="utf-8")
        EngagementState(name="t").save(p)
        assert EngagementState.load(p).name == "t"

    def test_save_overwrites_existing_atomically(self, tmp_path):
        p = tmp_path / "state.json"
        EngagementState(name="one").save(p)
        EngagementState(name="two").save(p)
        assert EngagementState.load(p).name == "two"

    def test_existing_state_is_never_truncated_on_failed_write(self, tmp_path, monkeypatch):
        # Simulate a crash during the temp write; the previously-saved state.json
        # must remain intact and loadable (that's the whole point of atomic save).
        p = tmp_path / "state.json"
        EngagementState(name="good").save(p)

        import pathlib
        real_write = pathlib.Path.write_text

        def boom(self, *a, **k):
            if self.name.endswith(".tmp"):
                raise OSError("disk full")
            return real_write(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "write_text", boom)
        try:
            EngagementState(name="new").save(p)
        except OSError:
            pass
        monkeypatch.undo()
        assert EngagementState.load(p).name == "good"   # old state survived
