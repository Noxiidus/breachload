"""Environment / tool detection."""

from breachload.core.environment import (
    KNOWN_TOOLS,
    available_tools,
    check_tools,
    check_wordlists,
    is_available,
)


class TestCheckTools:
    def test_covers_all_known_tools(self):
        names = {t.name for t in check_tools()}
        for role_tools in KNOWN_TOOLS.values():
            assert set(role_tools) <= names

    def test_status_has_role_and_present_flag(self):
        nmap = next(t for t in check_tools() if t.name == "nmap")
        assert nmap.role == "recon"
        assert nmap.present == (nmap.path is not None)

    def test_available_tools_is_subset(self):
        assert available_tools() <= {t.name for t in check_tools()}

    def test_is_available_false_for_nonsense(self):
        assert is_available("definitely_not_a_real_binary_xyz") is False


class TestWordlists:
    def test_returns_path_and_bool(self):
        for path, ok in check_wordlists():
            assert isinstance(path, str) and isinstance(ok, bool)
