"""EventHub — bridges the engine to connected dashboard clients.

The orchestrator's `on_event(event, message)` feeds `emit`, which broadcasts to
every subscribed client and keeps a replay log for late joiners. The
confirmation gate is bridged too: `request_confirm` (used as the orchestrator's
async confirm callback) broadcasts a confirm request and awaits the client's
approve/deny, delivered back via `resolve_confirm`.

Pure asyncio, no framework dependency — so it is fully unit-testable.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4


class EventHub:
    def __init__(self, replay_limit: int = 500) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._pending: dict[str, asyncio.Future] = {}
        self._log: list[dict] = []
        self._replay_limit = replay_limit
        self._last_state: dict | None = None

    # --- subscription -------------------------------------------------------
    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def log(self) -> list[dict]:
        return list(self._log)

    # --- broadcasting -------------------------------------------------------
    def emit(self, event: str, message: str) -> None:
        self._publish({"type": "event", "event": event, "message": message})

    def emit_state(self, payload: dict) -> None:
        """Push a full state snapshot. Not logged for replay (only the latest is kept)."""
        self._last_state = payload
        self._broadcast({"type": "state", "state": payload})

    @property
    def last_state(self) -> dict | None:
        return self._last_state

    def _publish(self, record: dict) -> None:
        self._log.append(record)
        if len(self._log) > self._replay_limit:
            self._log = self._log[-self._replay_limit:]
        self._broadcast(record)

    def _broadcast(self, record: dict) -> None:
        for queue in list(self._subscribers):
            queue.put_nowait(record)

    # --- confirmation gate --------------------------------------------------
    async def request_confirm(self, prompt: str) -> bool:
        confirm_id = uuid4().hex
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[confirm_id] = future
        self._publish({"type": "confirm", "id": confirm_id, "prompt": prompt})
        try:
            return await future
        finally:
            self._pending.pop(confirm_id, None)

    def resolve_confirm(self, confirm_id: str, approved: bool) -> bool:
        future = self._pending.get(confirm_id)
        if future is None or future.done():
            return False
        future.set_result(approved)
        return True

    def cancel_pending(self) -> int:
        """Deny every outstanding confirmation. Used by the kill-switch so a stop
        can't leave the engine blocked forever on a gate no client will answer.
        Returns the number of confirmations denied."""
        cancelled = 0
        for future in list(self._pending.values()):
            if not future.done():
                future.set_result(False)
                cancelled += 1
        return cancelled

    @property
    def pending_confirms(self) -> list[str]:
        return [cid for cid, fut in self._pending.items() if not fut.done()]
