"""
What every agent definition has in common.

This lives apart from any one agent so the second definition (copilot,
enrich, hunt - steps 3 and 4 of the design spec's build sequence) imports
its base from here rather than reaching into `triage.py` for a type that
has nothing to do with triage.
"""

from dataclasses import dataclass


@dataclass
class AgentDefinition:
    """
    Everything that distinguishes one agent from another.

    The design spec's four agents are the same loop with different entry
    conditions, so an agent is configuration - a prompt, an effort level, a
    cap - rather than an implementation. Adding one is a new file here plus
    a registry line; nothing in the runtime changes.
    """

    name: str
    system_prompt: str
    effort: str = "high"
    max_iterations: int = 40
