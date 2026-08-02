"""
Safety layer for the agent runtime.

BSOT reads adversary-authored input: phishing bodies, file strings, log lines.
The controls here are structural rather than prompt-only, because a prompt
instruction is exactly what an attacker gets to argue with.
"""

from enum import Enum
from typing import Sequence


class Tier(Enum):
    """What a tool is allowed to do without a human."""

    READ_ONLY = "read_only"
    CASE_WRITE = "case_write"
    EXTERNAL_MUTATION = "external_mutation"


# Groups whose every command only reads.
_READ_ONLY_GROUPS = {
    "file", "intel", "logs", "network", "data", "auth", "system",
    "malware", "phishing", "osint",
}

# Commands that mutate something outside this host. Listed by exact path
# because the blast radius is real: these change production firewall rules
# or hand a sample to a third party.
_EXTERNAL_MUTATION = {
    ("ir", "cf", "block"),
    ("ir", "cf", "bulk-block"),
    ("ir", "cf", "unblock"),
    ("ir", "contain"),
    ("malware", "submit"),
}

_CASE_WRITE_GROUPS = {"case", "report"}


def tier_for(path: Sequence[str]) -> Tier:
    """
    Classify a command path.

    Unknown commands are treated as externally mutating. Failing closed means a
    command added later is gated until someone classifies it deliberately,
    rather than silently becoming auto-runnable.
    """
    key = tuple(path)

    if key in _EXTERNAL_MUTATION:
        return Tier.EXTERNAL_MUTATION

    if not path:
        return Tier.EXTERNAL_MUTATION

    group = path[0]
    if group in _CASE_WRITE_GROUPS:
        return Tier.CASE_WRITE
    if group in _READ_ONLY_GROUPS:
        return Tier.READ_ONLY

    return Tier.EXTERNAL_MUTATION


def requires_approval(path: Sequence[str], tainted: bool) -> bool:
    """
    Whether a human must approve this call.

    External mutations always require approval. A tainted run - one that has
    ingested attacker-controlled content - may not mutate anything at all
    without a human, regardless of what the model concluded from that content.
    """
    tier = tier_for(path)
    if tier is Tier.EXTERNAL_MUTATION:
        return True
    return tainted and tier is not Tier.READ_ONLY
