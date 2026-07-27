"""Rate limiter — deterministic with injected clock and sleep."""

import asyncio

from breachload.core.ratelimit import RateLimiter


class _Fake:
    def __init__(self):
        self.t = 0.0
        self.slept: list[float] = []

    def now(self):
        return self.t

    async def sleep(self, s):
        self.slept.append(s)
        self.t += s


class TestRateLimiter:
    def test_first_call_does_not_sleep(self):
        f = _Fake()
        rl = RateLimiter(1.0, clock=f.now, sleep=f.sleep)
        assert asyncio.run(rl.wait()) == 0.0
        assert f.slept == []

    def test_throttles_when_too_soon(self):
        async def scenario():
            f = _Fake()
            rl = RateLimiter(1.0, clock=f.now, sleep=f.sleep)
            await rl.wait()          # last = 0
            f.t = 0.3                # only 0.3s elapsed
            slept = await rl.wait()  # must sleep 0.7
            return f, slept
        f, slept = asyncio.run(scenario())
        assert abs(slept - 0.7) < 1e-9
        assert f.slept == [0.7]

    def test_no_sleep_when_enough_elapsed(self):
        async def scenario():
            f = _Fake()
            rl = RateLimiter(1.0, clock=f.now, sleep=f.sleep)
            await rl.wait()
            f.t = 5.0                # plenty of time passed
            return f, await rl.wait()
        f, slept = asyncio.run(scenario())
        assert slept == 0.0 and f.slept == []

    def test_zero_interval_never_sleeps(self):
        f = _Fake()
        rl = RateLimiter(0.0, clock=f.now, sleep=f.sleep)
        assert asyncio.run(rl.wait()) == 0.0
        assert f.slept == []

    def test_negative_interval_clamped(self):
        assert RateLimiter(-5.0).min_interval == 0.0
