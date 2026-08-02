"""
Async utilities for BSOT.
Provides concurrent execution for bulk operations with rate limiting.
"""

import asyncio
import threading
import time
from typing import List, Callable, Any, Dict, TypeVar, Awaitable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

T = TypeVar('T')


@dataclass
class RateLimiter:
    """
    Token bucket rate limiter, safe to share across threads and event loops.

    A single limiter instance governs the aggregate rate for a service, so N
    concurrent workers sharing it still make at most `requests_per_second`
    requests per second combined.

    Attributes:
        requests_per_second: Maximum requests per second
        burst: Maximum burst size (default: same as requests_per_second)
    """
    requests_per_second: float
    burst: int = None

    _tokens: float = field(default=0, init=False)
    _last_update: float = field(default=0, init=False)
    _thread_lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    # asyncio.Lock binds to the running loop, so one is created per loop rather
    # than at import time (a module-level lock breaks on a second asyncio.run).
    _async_locks: dict = field(default_factory=dict, init=False)

    def __post_init__(self):
        if self.burst is None:
            self.burst = max(1, int(self.requests_per_second))
        self._tokens = float(self.burst)
        self._last_update = time.monotonic()

    def _take(self) -> float:
        """Consume a token, returning how long the caller must wait first."""
        now = time.monotonic()
        self._tokens = min(
            self.burst,
            self._tokens + (now - self._last_update) * self.requests_per_second,
        )
        self._last_update = now

        self._tokens -= 1
        if self._tokens < 0:
            # Debt is repaid by waiting; tokens stay negative so concurrent
            # callers queue behind each other instead of all sleeping the same
            # interval and then firing at once.
            return -self._tokens / self.requests_per_second
        return 0.0

    def _async_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._async_locks.get(loop)
        if lock is None:
            lock = asyncio.Lock()
            self._async_locks[loop] = lock
        return lock

    async def acquire(self):
        """Acquire a token, waiting if necessary."""
        async with self._async_lock():
            with self._thread_lock:
                wait = self._take()
        # Sleep outside the lock so other callers can compute their own slot.
        if wait > 0:
            await asyncio.sleep(wait)

    def acquire_sync(self):
        """Blocking form of acquire() for thread-pool callers."""
        with self._thread_lock:
            wait = self._take()
        if wait > 0:
            time.sleep(wait)


# Per-service rate limiters. Values are documented free-tier ceilings; paid
# tiers are higher, but limiting conservatively is the safe default.
SERVICE_RATE_LIMITS = {
    'virustotal': RateLimiter(4 / 60, burst=4),   # 4 req/MINUTE (public API)
    'abuseipdb': RateLimiter(1),                  # ~1 req/sec (1k/day free tier)
    'greynoise': RateLimiter(1),                  # community API ~1 req/sec
    'otx': RateLimiter(5),                        # 5 req/sec
    'urlscan': RateLimiter(2),                    # 2 req/sec
    'ipinfo': RateLimiter(10),                    # 10 req/sec
    'default': RateLimiter(10),                   # Default rate limit
}


class BulkExecutor:
    """
    Executes bulk operations with concurrency control and rate limiting.
    """
    
    def __init__(
        self,
        max_concurrent: int = 5,
        service: str = None,
        show_progress: bool = False
    ):
        """
        Initialize bulk executor.
        
        Args:
            max_concurrent: Maximum concurrent operations
            service: Service name for rate limiting
            show_progress: Show progress bar (requires rich)
        """
        self.max_concurrent = max_concurrent
        self.service = service
        self.show_progress = show_progress
        self.rate_limiter = SERVICE_RATE_LIMITS.get(service, SERVICE_RATE_LIMITS['default'])
    
    async def execute_async(
        self,
        items: List[Any],
        lookup_func: Callable[[Any], Awaitable[T]],
        on_complete: Callable[[Any, T], None] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute async lookups for all items.
        
        Args:
            items: List of items to process
            lookup_func: Async function to call for each item
            on_complete: Optional callback for each completed item
            
        Returns:
            List of results with 'item' and 'result' or 'error' keys
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)
        results = []
        
        async def process_item(item):
            async with semaphore:
                await self.rate_limiter.acquire()
                try:
                    result = await lookup_func(item)
                    if on_complete:
                        on_complete(item, result)
                    return {'item': item, 'result': result}
                except Exception as e:
                    return {'item': item, 'error': str(e)}
        
        # Create progress bar if requested
        if self.show_progress:
            try:
                from rich.progress import Progress
                with Progress() as progress:
                    task = progress.add_task("Processing...", total=len(items))
                    
                    async def process_with_progress(item):
                        result = await process_item(item)
                        progress.advance(task)
                        return result
                    
                    tasks = [process_with_progress(item) for item in items]
                    results = await asyncio.gather(*tasks)
            except ImportError:
                # Fall back to no progress bar
                tasks = [process_item(item) for item in items]
                results = await asyncio.gather(*tasks)
        else:
            tasks = [process_item(item) for item in items]
            results = await asyncio.gather(*tasks)
        
        return results
    
    def execute_sync(
        self,
        items: List[Any],
        lookup_func: Callable[[Any], T],
        on_complete: Callable[[Any, T], None] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute synchronous lookups using thread pool.
        
        Args:
            items: List of items to process
            lookup_func: Function to call for each item
            on_complete: Optional callback for each completed item
            
        Returns:
            List of results with 'item' and 'result' or 'error' keys
        """
        results = []
        completed = 0
        total = len(items)
        
        def process_item(item):
            nonlocal completed
            try:
                # Shared token bucket: the aggregate rate across all workers
                # stays within the service limit.
                self.rate_limiter.acquire_sync()
                result = lookup_func(item)
                if on_complete:
                    on_complete(item, result)
                completed += 1
                return {'item': item, 'result': result}
            except Exception as e:
                completed += 1
                return {'item': item, 'error': str(e)}
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            if self.show_progress:
                try:
                    from rich.progress import Progress
                    with Progress() as progress:
                        task = progress.add_task("Processing...", total=total)
                        futures = {executor.submit(process_item, item): item for item in items}
                        for future in as_completed(futures):
                            results.append(future.result())
                            progress.advance(task)
                except ImportError:
                    futures = {executor.submit(process_item, item): item for item in items}
                    for future in as_completed(futures):
                        results.append(future.result())
            else:
                futures = {executor.submit(process_item, item): item for item in items}
                for future in as_completed(futures):
                    results.append(future.result())
        
        return results


def bulk_lookup(
    items: List[Any],
    lookup_func: Callable[[Any], T],
    max_concurrent: int = 5,
    service: str = None,
    show_progress: bool = False
) -> List[Dict[str, Any]]:
    """
    Convenience function for bulk lookups.
    
    Args:
        items: List of items to process
        lookup_func: Function to call for each item
        max_concurrent: Maximum concurrent operations
        service: Service name for rate limiting
        show_progress: Show progress bar
        
    Returns:
        List of results
    
    Example:
        >>> results = bulk_lookup(
        ...     ["1.2.3.4", "evil.com"],
        ...     lambda x: virustotal_lookup(x),
        ...     service="virustotal"
        ... )
    """
    executor = BulkExecutor(
        max_concurrent=max_concurrent,
        service=service,
        show_progress=show_progress
    )
    return executor.execute_sync(items, lookup_func)


async def async_bulk_lookup(
    items: List[Any],
    lookup_func: Callable[[Any], Awaitable[T]],
    max_concurrent: int = 5,
    service: str = None,
    show_progress: bool = False
) -> List[Dict[str, Any]]:
    """
    Async version of bulk_lookup.
    
    Example:
        >>> results = await async_bulk_lookup(
        ...     ["1.2.3.4", "evil.com"],
        ...     async_virustotal_lookup,
        ...     service="virustotal"
        ... )
    """
    executor = BulkExecutor(
        max_concurrent=max_concurrent,
        service=service,
        show_progress=show_progress
    )
    return await executor.execute_async(items, lookup_func)

