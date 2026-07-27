"""Rate limiting for target-facing actions.

Enforces a minimum interval between executed actions so the agent doesn't hammer
a target. The clock and sleep are injectable so the behaviour is deterministically
testable without real time passing.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class RateLimiter:
    def __init__(
        self,
        min_interval: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.min_interval = max(0.0, min_interval)
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    async def wait(self) -> float:
        """Block until at least `min_interval` has passed since the last call.

        Returns the number of seconds slept (0 if no throttling was needed).
        """
        if self.min_interval <= 0:
            return 0.0
        now = self._clock()
        if self._last is not None:
            elapsed = now - self._last
            remaining = self.min_interval - elapsed
            if remaining > 0:
                await self._sleep(remaining)
                self._last = self._clock()
                return remaining
        self._last = self._clock()
        return 0.0
