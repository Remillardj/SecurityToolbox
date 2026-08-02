"""
Make rate limits visible to the model.

The shared token bucket already enforces correctness, but an agent that cannot
see the budget will happily queue a 12-minute fan-out and look hung. Surfacing
it lets the agent prefer cache and local sources, and say when a task is
rate-bound rather than stalling silently.

`build_budget_status_tool()` and `budget_status_tool()` are the tool half of
that contract, mirroring provenance's record_finding pair: this module knows
nothing about the runtime that dispatches them.

What this reports is the *configured* ceiling, not remaining tokens. The
executor runs each command in its own subprocess, so the limiter objects in
this process are never decremented by the agent's actual lookups - there is no
live token state to read. The numbers are still worth surfacing (they are what
makes a 50-IOC VirusTotal fan-out predictably a 12-minute job rather than a
mysterious hang), but they are a rate sheet, not a fuel gauge, and the tool
description says so rather than letting the model infer otherwise.
"""

import copy
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


_BUDGET_STATUS_TOOL_TEMPLATE: Dict[str, Any] = {
    "name": "budget_status",
    "description": (
        "Look up the per-service rate limits for third-party enrichment "
        "lookups, and optionally estimate how long a batch of them would "
        "take. Call this BEFORE fanning out across many indicators, so you "
        "can spend lookups on the ones that could change your assessment "
        "and tell the analyst when a task is rate-bound rather than "
        "appearing to hang. Note these are the configured ceilings, not "
        "remaining quota: this cannot tell you how much budget a previous "
        "run already consumed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "description": (
                    "Optional service to estimate for, e.g. 'virustotal'. "
                    "Omit to just list every service's limits."
                ),
            },
            "count": {
                "type": "integer",
                "description": (
                    "Optional number of lookups to estimate a duration for. "
                    "Requires 'service'."
                ),
            },
        },
        "required": [],
    },
}


def build_budget_status_tool() -> Dict[str, Any]:
    """A fresh copy of the budget_status tool schema (see note above)."""
    return copy.deepcopy(_BUDGET_STATUS_TOOL_TEMPLATE)


def budget_status_tool(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle a `budget_status` call.

    Never raises: a malformed call comes back as a result the model can read
    and correct, the same contract record_finding follows, because an
    exception here would end the whole run.
    """
    try:
        service = params.get("service") if isinstance(params, dict) else None
        count = params.get("count") if isinstance(params, dict) else None
    except AttributeError:
        return {"ok": False, "error": "params must be an object"}

    result: Dict[str, Any] = {
        "ok": True,
        "services": budget_status(),
        "note": (
            "Configured ceilings, not remaining quota. Each command runs in "
            "its own process, so prior usage is not tracked here."
        ),
    }

    if count is not None:
        if not service:
            return {
                "ok": False,
                "error": "'count' requires 'service'",
            }
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return {
                "ok": False,
                "error": f"'count' must be a non-negative integer, got {count!r}",
            }
        result["estimate"] = {
            "service": service,
            "count": count,
            "seconds": round(estimate_duration(service, count), 2),
        }

    return result
