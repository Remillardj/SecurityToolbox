"""
Finding attribution.

A confident but fabricated finding is worse than a missing one: it gets copied
into an incident report and believed. Attribution is therefore enforced by the
constructor, not by asking the model to behave.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

VALID_CONFIDENCE = ("low", "medium", "high")


class UnsourcedFinding(ValueError):
    """Raised when a claim arrives with no command behind it."""


@dataclass
class Finding:
    """One claim, and the command that produced it."""

    claim: str
    source_command: str
    exit_code: int
    evidence: str = ""
    confidence: str = "medium"

    def __post_init__(self):
        if not self.source_command.strip():
            raise UnsourcedFinding(
                f"finding {self.claim!r} has no source command; every claim "
                f"must cite the command that produced it"
            )
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError(
                f"confidence must be one of {VALID_CONFIDENCE}, "
                f"got {self.confidence!r}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim,
            "source_command": self.source_command,
            "exit_code": self.exit_code,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class FindingLog:
    """Every finding recorded during one run."""

    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
