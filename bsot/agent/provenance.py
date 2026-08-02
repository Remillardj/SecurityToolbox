"""
Finding attribution.

A confident but fabricated finding is worse than a missing one: it gets copied
into an incident report and believed. Attribution is therefore enforced by the
constructor, not by asking the model to behave.

This module is deliberately provider-agnostic and dependency-free: it must
never import bridge, safety, executor, or anything else from the wider `bsot`
package. `RECORD_FINDING_TOOL` and `record_finding()` below are the tool half
of that contract - the runtime (Task 10) and the deferred-tool loader
(Task 11) wire them in, but this module has no idea either exists.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List

VALID_CONFIDENCE = ("low", "medium", "high")

# Deliberately strict, not normalized: a model that sends "High" gets a
# rejection it can read (via the record_finding handler below) and retry
# with the right value, same as any other malformed call. Silently
# lower-casing it would make this constructor start "helping" - exactly the
# behavior the frozen dataclass and the source_command check exist to avoid
# elsewhere. It also leaves no ambiguity about what's actually stored: the
# three literal values here are the only three values a case will ever see.


class UnsourcedFinding(ValueError):
    """Raised when a claim arrives with no command behind it."""


@dataclass(frozen=True)
class Finding:
    """
    One claim, and the command that produced it.

    Frozen: enforcement that only holds for the instant of construction is
    not enforcement. Without `frozen=True`, `f.source_command = ""` after a
    valid build would be accepted silently and the now-unsourced finding
    would serialize straight into the case - the exact failure mode the
    constructor check exists to prevent. Nothing downstream needs to mutate
    a Finding once made: Task 7 only reads one, Task 10 replaces the whole
    log rather than editing entries, and Task 12 reads three attributes.
    """

    claim: str
    source_command: str
    exit_code: int
    evidence: str = ""
    confidence: str = "medium"

    def __post_init__(self):
        # claim: unvalidated, an empty or non-str claim asserts nothing but
        # still inflates the finding count and renders as an empty bullet
        # in the case. Guarded the same way as source_command below.
        if not isinstance(self.claim, str):
            raise TypeError(
                f"Finding.claim must be str, got {type(self.claim).__name__}"
            )
        if not self.claim.strip():
            raise ValueError("Finding.claim must not be blank")

        # source_command: the attribution the rest of this module exists to
        # enforce. A non-str value (None, 0, [], True, ...) must fail here
        # with a clear TypeError from this constructor's own contract,
        # rather than a layer down as a confusing AttributeError from
        # `.strip()` - same reasoning as the content/source guards in
        # safety.py's frame_untrusted.
        if not isinstance(self.source_command, str):
            raise TypeError(
                f"Finding.source_command must be str, got "
                f"{type(self.source_command).__name__}"
            )
        if not self.source_command.strip():
            raise UnsourcedFinding(
                f"finding {self.claim!r} has no source command; every claim "
                f"must cite the command that produced it"
            )

        # evidence: must be a real string. Without this guard, bytes (e.g.
        # b"\xff\xfeMZ") would serialize under `default=str` as a mangled
        # Python repr and be presented to an analyst as evidence; None would
        # need special-casing everywhere it's read. The "" default is itself
        # a str, so it passes unchanged.
        if not isinstance(self.evidence, str):
            raise TypeError(
                f"Finding.evidence must be str, got {type(self.evidence).__name__}"
            )

        # confidence: deliberately NOT normalized (no .strip().lower()).
        # See the module-level note near VALID_CONFIDENCE for the reasoning.
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
        # A non-Finding here would otherwise fail later, at serialization,
        # as an AttributeError on whatever `.to_dict()`-less object got in -
        # confusing and far from the mistake. Fail at the point of insertion
        # instead, with a message that names the actual contract.
        if not isinstance(finding, Finding):
            raise TypeError(
                f"FindingLog.add expects a Finding, got {type(finding).__name__}"
            )
        # No dedup: two findings sharing every field are a legitimate result
        # of running the same command twice (e.g. re-checking after a fix),
        # and deciding "which one is the real one" is not this module's call
        # to make. Both are kept.
        self.findings.append(finding)

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def counts_by_confidence(self) -> Dict[str, int]:
        """Triage summary: how many findings at each confidence level."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "counts_by_confidence": self.counts_by_confidence(),
        }


# --------------------------------------------------------------------------
# The record_finding tool
#
# Design spec (2026-08-02-bsot-agents-design.md, "Provenance"): findings
# enter a case only through record_finding, and it is one of the handful of
# tools NOT subject to deferred loading, because nearly every run needs it.
# `bridge.build_catalogue()` only walks the Click command tree, so it
# structurally cannot emit a schema for a tool with no backing CLI command -
# this one is hand-written, in the same shape bridge.py emits, so the
# runtime can treat every tool uniformly regardless of where it came from.
#
# This module still does not import bridge, the runtime, or the provider -
# it publishes the schema and a plain-dict-in, plain-dict-out handler.
# Wiring dispatch (Task 10) and exempting this tool from deferred loading
# (Task 11) both happen elsewhere.
# --------------------------------------------------------------------------

RECORD_FINDING_TOOL: Dict[str, Any] = {
    "name": "record_finding",
    "description": (
        "Record one investigative finding in this case. Every finding must "
        "cite the exact command that produced it (source_command) and that "
        "command's exit_code, plus the relevant excerpt of its output that "
        "supports the claim (evidence). A claim with no real command behind "
        "it is rejected - do not call this for something you have not "
        "actually run and observed in this session. Call it once per "
        "distinct claim, as you go, not batched at the end."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "claim": {
                "type": "string",
                "description": "The finding, stated as a single factual claim.",
            },
            "source_command": {
                "type": "string",
                "description": (
                    "The exact command you ran that produced this finding, "
                    "e.g. 'bsot malware pe sample.exe --json'."
                ),
            },
            "exit_code": {
                "type": "integer",
                "description": "The exit code returned by source_command.",
            },
            "evidence": {
                "type": "string",
                "description": (
                    "The relevant excerpt of source_command's output that "
                    "supports the claim."
                ),
            },
            "confidence": {
                "type": "string",
                "enum": list(VALID_CONFIDENCE),
                "default": "medium",
                "description": "How confident this claim is: low, medium, or high.",
            },
        },
        "required": ["claim", "source_command", "exit_code"],
    },
}


def record_finding(log: FindingLog, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handler for the `record_finding` tool.

    Builds a Finding from model-supplied params and appends it to `log`. A
    validation failure - an unsourced claim, an unknown confidence value, a
    wrong-typed field, or a missing required key - comes back as a result
    dict the model can read and correct from, rather than an exception that
    would kill the agent loop and silently drop the finding along with it.
    """
    try:
        finding = Finding(
            claim=params["claim"],
            source_command=params["source_command"],
            exit_code=params["exit_code"],
            evidence=params.get("evidence", ""),
            confidence=params.get("confidence", "medium"),
        )
    except KeyError as exc:
        return {
            "recorded": False,
            "error": f"record_finding is missing required field: {exc.args[0]}",
        }
    except (TypeError, ValueError) as exc:
        # Covers UnsourcedFinding too, since it subclasses ValueError.
        return {"recorded": False, "error": str(exc)}

    log.add(finding)
    return {"recorded": True, "count": len(log.findings)}
