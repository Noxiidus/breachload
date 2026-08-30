"""FastAPI dashboard server.

Serves a self-contained dashboard and bridges the engine to the browser:
- `GET /`            the dashboard page
- `GET /api/state`   current structured engagement state (JSON)
- `GET /api/report`  the Markdown report
- `WS  /ws`          live event stream + confirmation replies

FastAPI is imported here (not in the CLI top-level) so the core tool works
without the optional web dependency installed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import ValidationError

from ..core.state import EngagementState
from ..report.engine import render_markdown
from .dashboard import DASHBOARD_HTML
from .hub import EventHub


def create_app(
    hub: EventHub,
    state_path: Path,
    on_startup: Callable[[], Awaitable[None]] | None = None,
    stopper: Callable[[], None] | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if on_startup is not None:
            await on_startup()
        yield

    app = FastAPI(title="breachload dashboard", lifespan=lifespan)
    app.state.hub = hub
    app.state.state_path = Path(state_path)
    app.state.stopper = stopper

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return DASHBOARD_HTML

    @app.get("/api/state")
    async def api_state() -> JSONResponse:
        state = _load_state(app.state.state_path)
        return JSONResponse(state.model_dump() if state else {})

    @app.get("/api/report", response_class=PlainTextResponse)
    async def api_report() -> str:
        state = _load_state(app.state.state_path)
        return render_markdown(state) if state else "# No state yet\n"

    @app.post("/api/stop")
    async def api_stop() -> JSONResponse:
        if app.state.stopper is None:
            return JSONResponse({"ok": False, "reason": "no running engagement"}, status_code=409)
        app.state.stopper()
        return JSONResponse({"ok": True})

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        hub: EventHub = websocket.app.state.hub
        queue = hub.subscribe()
        for record in hub.log:          # replay history for late joiners
            await websocket.send_json(record)
        if hub.last_state is not None:  # bring a late joiner up to date
            await websocket.send_json({"type": "state", "state": hub.last_state})

        async def _pump() -> None:
            while True:
                await websocket.send_json(await queue.get())

        async def _recv() -> None:
            while True:
                data = await websocket.receive_json()
                if data.get("type") == "confirm":
                    hub.resolve_confirm(str(data.get("id", "")), bool(data.get("approved")))

        pump = asyncio.create_task(_pump())
        recv = asyncio.create_task(_recv())
        try:
            await asyncio.wait({pump, recv}, return_when=asyncio.FIRST_COMPLETED)
        except WebSocketDisconnect:
            pass
        finally:
            pump.cancel()
            recv.cancel()
            hub.unsubscribe(queue)
            # If the last client leaves with a confirmation still pending, deny it
            # so the engine isn't blocked forever on a gate no one can answer.
            if hub.subscriber_count == 0:
                hub.cancel_pending()

    return app


def _load_state(state_path: Path) -> EngagementState | None:
    """Load state, or None if it's missing or corrupt.

    A truncated (interrupted pre-atomic-save) or hand-edited state.json must not
    turn every dashboard request into an HTTP 500 - the API degrades to an empty
    state instead, matching the CLI's graceful corrupt-state handling.
    """
    if not state_path.exists():
        return None
    try:
        return EngagementState.load(state_path)
    except (ValueError, ValidationError):
        return None
