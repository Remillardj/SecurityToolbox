"""
Make rate limits visible to the model.

The shared token bucket already enforces correctness, but an agent that cannot
see the budget will happily queue a 12-minute fan-out and look hung. Surfacing
it lets the agent prefer cache and local sources, and say when a task is
rate-bound rather than stalling silently.
"""

from typing import Any, Dict


def budget_status() -> Dict[str, Dict[str, Any]]:
    """Per-service rate limits, as the model should see them."""
    from bsot.async_utils import SERVICE_RATE_LIMITS

    status: Dict[str, Dict[str, Any]] = {}
    for service, limiter in SERVICE_RATE_LIMITS.items():
        status[service] = {
            "requests_per_second": round(limiter.requests_per_second, 4),
            "requests_per_minute": round(limiter.requests_per_second * 60, 2),
            "burst": limiter.burst,
        }
    return status


def estimate_duration(service: str, count: int) -> float:
    """Seconds a batch of `count` lookups against `service` will take.

    Assumes a fresh rate-limit window with no prior calls. If calls have already
    consumed tokens in this window, the actual wait will be longer.
    """
    from bsot.async_utils import SERVICE_RATE_LIMITS

    limiter = SERVICE_RATE_LIMITS.get(service, SERVICE_RATE_LIMITS["default"])
    if count <= limiter.burst:
        return 0.0
    return (count - limiter.burst) / limiter.requests_per_second
