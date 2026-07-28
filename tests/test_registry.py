"""Tool registry and third-party plugin discovery."""

import breachload.tools.registry as reg
from breachload.tools.base import ToolAdapter, ToolResult
from breachload.tools.registry import (
    _as_adapters,
    allowed_binaries,
    default_registry,
    merge_plugins,
)


class _PluginAdapter(ToolAdapter):
    def __init__(self, name="plugin-scan", binary="plugscan"):
        super().__init__(name=name, binary=binary, capabilities=["http"])

    def build_command(self, target, **kwargs):
        return [self.binary, target]

    def parse(self, result: ToolResult, state):
        return []


class _FakeEP:
    def __init__(self, name, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


class TestDefaultRegistry:
    def test_builtins_present(self):
        r = default_registry(load_plugins=False)
        assert {"nmap", "ffuf", "nuclei"} <= set(r)

    def test_allowed_binaries_derived(self):
        assert "nmap" in allowed_binaries(default_registry(load_plugins=False))


class TestAsAdapters:
    def test_instance(self):
        adapters = _as_adapters(_PluginAdapter())
        assert adapters and isinstance(adapters[0], ToolAdapter)

    def test_class_is_instantiated(self):
        assert isinstance(_as_adapters(_PluginAdapter)[0], ToolAdapter)

    def test_list_of_adapters(self):
        assert len(_as_adapters([_PluginAdapter("a"), _PluginAdapter("b")])) == 2

    def test_non_adapter_filtered_out(self):
        assert _as_adapters(object()) == []


class TestMergePlugins:
    def test_adds_plugin_adapter(self, monkeypatch):
        monkeypatch.setattr(reg, "_plugin_entry_points",
                            lambda: [_FakeEP("p", _PluginAdapter())])
        registry = merge_plugins({})
        assert "plugin-scan" in registry

    def test_plugin_cannot_shadow_builtin(self, monkeypatch):
        builtin = default_registry(load_plugins=False)
        original = builtin["nmap"]
        monkeypatch.setattr(reg, "_plugin_entry_points",
                            lambda: [_FakeEP("evil", _PluginAdapter(name="nmap", binary="evil"))])
        merge_plugins(builtin)
        assert builtin["nmap"] is original          # built-in preserved

    def test_broken_plugin_is_skipped(self, monkeypatch):
        class _Boom:
            name = "boom"

            def load(self):
                raise RuntimeError("bad plugin")

        monkeypatch.setattr(reg, "_plugin_entry_points",
                            lambda: [_Boom(), _FakeEP("ok", _PluginAdapter())])
        registry = merge_plugins({})
        assert "plugin-scan" in registry           # good one still loaded
