"""Web dashboard: EventHub logic and the FastAPI endpoints."""

import asyncio

from fastapi.testclient import TestClient

from breachload.core.state import EngagementState, Finding, Service, Severity
from breachload.web.hub import EventHub
from breachload.web.server import create_app


class TestEventHub:
    def test_emit_broadcasts_and_logs(self):
        async def scenario():
            hub = EventHub()
            q = hub.subscribe()
            hub.emit("note", "hello")
            rec = await asyncio.wait_for(q.get(), 1)
            return hub, rec
        hub, rec = asyncio.run(scenario())
        assert rec == {"type": "event", "event": "note", "message": "hello"}
        assert hub.log[-1]["message"] == "hello"

    def test_late_subscriber_gets_replay_log(self):
        hub = EventHub()
        hub.emit("phase", "recon")
        # A subscriber that joins later sees history via hub.log (server replays it).
        assert any(r["message"] == "recon" for r in hub.log)

    def test_confirm_roundtrip_approved(self):
        async def scenario():
            hub = EventHub()
            q = hub.subscribe()
            task = asyncio.create_task(hub.request_confirm("run nmap?"))
            req = await asyncio.wait_for(q.get(), 1)
            assert req["type"] == "confirm"
            hub.resolve_confirm(req["id"], True)
            return await asyncio.wait_for(task, 1)
        assert asyncio.run(scenario()) is True

    def test_confirm_roundtrip_denied(self):
        async def scenario():
            hub = EventHub()
            q = hub.subscribe()
            task = asyncio.create_task(hub.request_confirm("exploit?"))
            req = await asyncio.wait_for(q.get(), 1)
            hub.resolve_confirm(req["id"], False)
            return await asyncio.wait_for(task, 1)
        assert asyncio.run(scenario()) is False

    def test_resolve_unknown_confirm_is_noop(self):
        assert EventHub().resolve_confirm("nope", True) is False

    def test_emit_state_stores_last_and_broadcasts(self):
        async def scenario():
            hub = EventHub()
            q = hub.subscribe()
            hub.emit_state({"phase": "recon"})
            return hub, await asyncio.wait_for(q.get(), 1)
        hub, rec = asyncio.run(scenario())
        assert rec == {"type": "state", "state": {"phase": "recon"}}
        assert hub.last_state == {"phase": "recon"}

    def test_state_is_not_in_replay_log(self):
        hub = EventHub()
        hub.emit_state({"phase": "vuln"})
        assert hub.log == []                # state snapshots aren't replayed as events

    def test_replay_limit_trims_log(self):
        hub = EventHub(replay_limit=5)
        for i in range(20):
            hub.emit("note", str(i))
        assert len(hub.log) == 5
        assert hub.log[-1]["message"] == "19"


def _app_with_state(tmp_path):
    state = EngagementState(name="web")
    host = state.upsert_host("10.10.10.5")
    host.upsert_service(Service(port=80, name="http", product="Apache"))
    state.add_finding(Finding(title="Test finding", severity=Severity.HIGH, host="10.10.10.5"))
    state_path = tmp_path / "state.json"
    state.save(state_path)
    return create_app(EventHub(), state_path)


class TestServer:
    def test_index_serves_dashboard(self, tmp_path):
        client = TestClient(_app_with_state(tmp_path))
        r = client.get("/")
        assert r.status_code == 200 and "breachload" in r.text

    def test_api_state(self, tmp_path):
        client = TestClient(_app_with_state(tmp_path))
        data = client.get("/api/state").json()
        assert "10.10.10.5" in data["hosts"]
        assert data["findings"][0]["title"] == "Test finding"

    def test_api_state_empty_when_no_file(self, tmp_path):
        client = TestClient(create_app(EventHub(), tmp_path / "missing.json"))
        assert client.get("/api/state").json() == {}

    def test_api_report(self, tmp_path):
        client = TestClient(_app_with_state(tmp_path))
        r = client.get("/api/report")
        assert "# Engagement report" in r.text and "Test finding" in r.text

    def test_on_startup_is_invoked_via_lifespan(self, tmp_path):
        called = []

        async def boot():
            called.append(True)

        app = create_app(EventHub(), tmp_path / "s.json", on_startup=boot)
        with TestClient(app) as client:   # entering the context runs the lifespan
            client.get("/")
        assert called == [True]

    def test_ws_replays_log_on_connect(self, tmp_path):
        hub = EventHub()
        hub.emit("phase", "== entering recon ==")
        hub.emit("note", "port 80 open")
        app = create_app(hub, tmp_path / "state.json")
        with TestClient(app).websocket_connect("/ws") as ws:
            first = ws.receive_json()
            second = ws.receive_json()
        assert first["message"] == "== entering recon =="
        assert second["message"] == "port 80 open"

    def test_ws_sends_last_state_on_connect(self, tmp_path):
        hub = EventHub()
        hub.emit_state({"phase": "vuln_analysis", "hosts": {}})
        app = create_app(hub, tmp_path / "state.json")
        with TestClient(app).websocket_connect("/ws") as ws:
            msg = ws.receive_json()
        assert msg["type"] == "state" and msg["state"]["phase"] == "vuln_analysis"

    def test_stop_endpoint_calls_stopper(self, tmp_path):
        called = []
        app = create_app(EventHub(), tmp_path / "s.json", stopper=lambda: called.append(True))
        r = TestClient(app).post("/api/stop")
        assert r.status_code == 200 and r.json()["ok"] is True and called == [True]

    def test_stop_endpoint_without_stopper(self, tmp_path):
        app = create_app(EventHub(), tmp_path / "s.json")
        r = TestClient(app).post("/api/stop")
        assert r.status_code == 409 and r.json()["ok"] is False

    def test_ws_client_confirm_message_is_handled(self, tmp_path):
        # The full confirm roundtrip is covered by the EventHub unit tests. Here we
        # verify the WS replay path delivers a seeded event and the receive path
        # accepts a client confirm reply without breaking the connection.
        hub = EventHub()
        hub.emit("phase", "seeded")
        app = create_app(hub, tmp_path / "state.json")
        with TestClient(app).websocket_connect("/ws") as ws:
            assert ws.receive_json()["message"] == "seeded"
            ws.send_json({"type": "confirm", "id": "unknown", "approved": True})
