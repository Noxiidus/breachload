"""Local-LLM planner backend (Ollama / LM Studio / OpenAI-compatible)."""

import json

import pytest

from breachload.core.llm import Planner
from breachload.core.state import EngagementState, Phase


class _FakeResp:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


@pytest.fixture
def monkey_local_llm(monkeypatch):
    """Return a helper that patches urllib.request.urlopen to serve a payload."""

    def _patch(payload: dict, path_hits: list[str] | None = None):
        import urllib.request
        captured: list[str] = []

        def fake_urlopen(req, timeout=30):
            captured.append(req.full_url)
            return _FakeResp(json.dumps(payload).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        if path_hits is not None:
            path_hits.append(captured)
        return captured

    return _patch


def _tools():
    from breachload.tools.registry import default_registry
    return [{"name": a.name, "risk": a.risk.name, "capabilities": a.capabilities}
            for a in default_registry(load_plugins=False).values()]


class TestLocalBackend:
    def test_online_true_when_local_url_set(self, monkeypatch):
        monkeypatch.setenv("BREACHLOAD_LOCAL_LLM_URL", "http://127.0.0.1:11434")
        assert Planner().online is True

    def test_openai_chat_completions_response(self, monkeypatch, monkey_local_llm):
        monkeypatch.setenv("BREACHLOAD_LOCAL_LLM_URL", "http://127.0.0.1:1234/v1")
        monkeypatch.setenv("BREACHLOAD_LOCAL_LLM_MODEL", "llama3")
        monkey_local_llm({"choices": [{"message": {
            "content": '{"action":"phase_complete","rationale":"nothing left"}'}}]})
        st = EngagementState(name="t", phase=Phase.RECON)
        plan = Planner().next_action(st, _tools())
        assert plan.action == "phase_complete"

    def test_falls_back_to_heuristic_on_bad_response(self, monkeypatch, monkey_local_llm):
        monkeypatch.setenv("BREACHLOAD_LOCAL_LLM_URL", "http://127.0.0.1:11434")
        monkey_local_llm({"unexpected": "shape"})
        st = EngagementState(name="t", phase=Phase.RECON)
        plan = Planner().next_action(st, _tools())
        # Heuristic decides something deterministic even with no state.
        assert plan.action in ("run", "phase_complete")

    def test_local_url_takes_priority_over_anthropic_key(self, monkeypatch):
        monkeypatch.setenv("BREACHLOAD_LOCAL_LLM_URL", "http://127.0.0.1:11434")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake")
        p = Planner()
        assert p._local_url and p._client is None

    def test_no_env_uses_heuristic(self, monkeypatch):
        monkeypatch.delenv("BREACHLOAD_LOCAL_LLM_URL", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        p = Planner()
        assert not p.online
