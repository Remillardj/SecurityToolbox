"""Agent definitions: prompt, effort, and limits per agent."""

from typing import Dict, List

from .base import AgentDefinition
from .triage import TRIAGE

_REGISTRY: Dict[str, AgentDefinition] = {
    TRIAGE.name: TRIAGE,
}


def list_definitions() -> List[str]:
    """Names of every registered agent."""
    return sorted(_REGISTRY)


def get_definition(name: str) -> AgentDefinition:
    """Look up one agent definition. Raises KeyError if unknown."""
    if name not in _REGISTRY:
        raise KeyError(
            f"unknown agent {name!r}; known agents: {', '.join(list_definitions())}"
        )
    return _REGISTRY[name]


__all__ = ["AgentDefinition", "get_definition", "list_definitions"]
