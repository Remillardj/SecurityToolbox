"""Tests for the shared rate limiter."""

import asyncio
import time

from bsot.async_utils import RateLimiter, BulkExecutor, SERVICE_RATE_LIMITS


class TestTokenBucket:
    def test_burst_is_immediate(self):
        limiter = RateLimiter(10, burst=5)
        start = time.monotonic()
        for _ in range(5):
            limiter.acquire_sync()

        assert time.monotonic() - start < 0.05

    def test_throttles_beyond_burst(self):
        limiter = RateLimiter(20, burst=1)
        limiter.acquire_sync()

        start = time.monotonic()
        limiter.acquire_sync()
        limiter.acquire_sync()
        elapsed = time.monotonic() - start

        # Two extra requests at 20/sec => ~0.1s
        assert 0.06 < elapsed < 0.3

    def test_aggregate_rate_across_threads(self):
        """N workers sharing one limiter must not multiply the rate by N."""
        limiter = RateLimiter(20, burst=1)
        executor = BulkExecutor(max_concurrent=5)
        executor.rate_limiter = limiter

        start = time.monotonic()
        results = executor.execute_sync(list(range(10)), lambda x: x)
        elapsed = time.monotonic() - start

        assert len(results) == 10
        # 10 requests at 20/sec is ~0.45s minimum. With the old per-thread
        # sleep, 5 workers finished in ~0.1s (a 5x overshoot).
        assert elapsed > 0.35, f"rate limit not enforced across threads ({elapsed:.3f}s)"


class TestAsyncLimiter:
    def test_survives_multiple_event_loops(self):
        """A module-level asyncio.Lock breaks on the second asyncio.run()."""
        limiter = RateLimiter(100, burst=10)

        async def use():
            await limiter.acquire()

        asyncio.run(use())
        asyncio.run(use())  # must not raise "attached to a different loop"

    def test_async_aggregate_rate(self):
        limiter = RateLimiter(20, burst=1)

        async def run():
            start = time.monotonic()
            await asyncio.gather(*(limiter.acquire() for _ in range(6)))
            return time.monotonic() - start

        elapsed = asyncio.run(run())
        assert elapsed > 0.15, f"concurrent acquires not serialized ({elapsed:.3f}s)"


class TestServiceLimits:
    def test_virustotal_is_per_minute(self):
        """VT public API allows 4 requests per MINUTE, not per second."""
        vt = SERVICE_RATE_LIMITS["virustotal"]
        assert vt.requests_per_second < 0.1, "VT limit looks like req/sec, not req/min"
        assert vt.burst == 4
