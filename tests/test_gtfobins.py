"""Offline GTFOBins lookup."""

from breachload.analysis.gtfobins import known_binaries, lookup


class TestLookup:
    def test_find_has_suid_and_sudo(self):
        entry = lookup("find")
        assert "suid" in entry and "sudo" in entry
        assert "/bin/sh" in entry["suid"]

    def test_basename_is_used(self):
        assert lookup("/usr/bin/vim") == lookup("vim")
        assert lookup("vim")   # non-empty

    def test_case_insensitive(self):
        assert lookup("PYTHON3") == lookup("python3")

    def test_unknown_binary_is_empty(self):
        assert lookup("totally-not-a-binary") == {}

    def test_known_binaries_listed(self):
        known = known_binaries()
        assert {"find", "vim", "python3", "tar", "nmap"} <= set(known)
