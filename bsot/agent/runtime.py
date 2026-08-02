"""
The agent loop.

This is the only module aware of the execution model. Everything it depends
on - the bridge, safety, provenance, budget - is provider-agnostic, so
replacing this file swaps local execution for hosted without touching the
rest (Task 11 appends an AnthropicProvider to this same file rather than
introducing a second provider-aware module).

Two corrections vs. the plan's original skeleton, both load-bearing:

1. `record_finding` is a hand-written tool (bsot.agent.provenance), not a
   CLI command - `build_catalogue()` only walks the Click tree, so this tool
   has no `_command_path` and no entry in the catalogue at all. It is
   dispatched by name *before* the catalogue lookup. Skipping this dispatch
   (or routing it through the catalogue lookup) means every finding a model
   tries to record is silently lost as an "unknown tool".
2. A command result's stdout/stderr can both be empty - a timeout, a
   missing binary, a signal-killed child - while the only diagnostic lives
   in `CommandResult.error`. `_content_for_framing` falls back to it rather
   than framing an empty block that tells the model nothing went wrong.
"""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .bridge import build_catalogue
from .definitions import get_definition
from .executor import CommandResult, run_command
from .provenance import FindingLog, build_record_finding_tool, record_finding
from .safety import RunState, frame_untrusted, requires_approval


@dataclass
class ToolCall:
    """One tool invocation requested by the model."""

    name: str
    params: Dict[str, Any] = field(default_factory=dict)


def _tool_for(tool_name: str, catalogue: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Look up a catalogue entry (schema + dispatch metadata) by tool name."""
    for tool in catalogue:
        if tool["name"] == tool_name:
            return tool
    return None


def _content_for_framing(result: CommandResult) -> str:
    """
    The text handed to `frame_untrusted` for one command result.

    stdout is preferred, then stderr, then `result.error` - never blank.
    `run_command` guarantees `.error` is populated whenever a command fails
    with nothing on either stream (timeout, missing binary, signal death,
    an otherwise-silent nonzero exit), but the final fallback below still
    covers the case none of the three carry anything, so this function
    itself never hands `frame_untrusted` an empty string.
    """
    if result.stdout:
        return result.stdout
    if result.stderr:
        return result.stderr
    if result.error:
        return result.error
    return (
        f"(command exited {result.exit_code} with no stdout, stderr, "
        "or diagnostic message)"
    )


class AgentRun:
    """One execution of one agent."""

    def __init__(self, agent: str, provider, max_iterations: Optional[int] = None):
        self.definition = get_definition(agent)
        self.provider = provider
        self.run_id = f"run-{uuid.uuid4().hex[:12]}"
        self.max_iterations = max_iterations or self.definition.max_iterations
        self.catalogue = build_catalogue()
        # record_finding has no backing Click command, so it is not (and
        # cannot be) part of `catalogue` - it is appended here purely for
        # what gets shown to the provider. Dispatch still keys off the
        # catalogue-free special case in `execute()` below.
        self.tools: List[Dict[str, Any]] = self.catalogue + [build_record_finding_tool()]
        self.state = RunState()
        self.findings = FindingLog()
        # Failed record_finding attempts (validation rejected by
        # provenance.Finding): tracked separately from the transcript so a
        # caller can cheaply ask "did the model try and fail to report
        # something?" without walking every transcript entry.
        self.failed_findings: List[Dict[str, Any]] = []
        self.transcript: List[Dict[str, Any]] = []
        self.pending_approval: List[Dict[str, Any]] = []

    def execute(self, task: str) -> None:
        """Run the loop until the provider stops or the cap is reached."""
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.definition.system_prompt},
            {"role": "user", "content": task},
        ]

        for _ in range(self.max_iterations):
            call = self.provider.next_step(messages, self.tools)
            if call is None:
                break

            if call.name == "record_finding":
                self._dispatch_record_finding(call, messages)
                continue

            tool = _tool_for(call.name, self.catalogue)
            if tool is None:
                self.transcript.append({
                    "tool": call.name, "executed": False,
                    "error": "unknown tool",
                })
                continue

            path = tool["_command_path"]

            if requires_approval(path, self.state.tainted):
                entry = {
                    "tool": call.name,
                    "command_path": path,
                    "params": call.params,
                    "executed": False,
                    "reason": "requires human approval",
                }
                self.pending_approval.append(entry)
                self.transcript.append(entry)
                continue

            # The runtime already holds the catalogue entry for this tool,
            # so its param metadata and JSON support are passed straight
            # through rather than making the executor re-look them up (and,
            # for any path outside the catalogue, this also bypasses the
            # executor's own catalogue-refusal guard - correct here because
            # `tool` above already proves this path came from the
            # catalogue).
            result = run_command(
                path,
                call.params,
                param_meta=tool["_params"],
                supports_json=tool["_supports_json"],
            )
            framed = frame_untrusted(_content_for_framing(result), source=result.command)
            self.state.record_untrusted(result.command)

            self.transcript.append({
                "tool": call.name,
                "command": result.command,
                "exit_code": result.exit_code,
                "executed": True,
                "framed_output": framed,
            })
            messages.append({"role": "user", "content": framed})

    def _dispatch_record_finding(
        self, call: ToolCall, messages: List[Dict[str, Any]]
    ) -> None:
        """
        Handle a `record_finding` call.

        Unlike every other tool, this result is our own dict - not command
        output an adversary-controlled artifact could have influenced - so
        it must NOT go through `frame_untrusted` and must NOT taint the run
        via `state.record_untrusted`. A validation failure comes back from
        `record_finding()` as a result dict, not an exception, so it is fed
        back to the model the same way a success is, and tracked in
        `failed_findings` so a failure that the model never retries is still
        visible after the run ends.
        """
        result = record_finding(self.findings, call.params)
        recorded = bool(result.get("recorded"))

        entry: Dict[str, Any] = {
            "tool": call.name,
            "executed": True,
            "recorded": recorded,
        }
        if not recorded:
            entry["error"] = result.get("error")
            self.failed_findings.append({
                "params": call.params,
                "error": result.get("error"),
            })
        self.transcript.append(entry)
        messages.append({"role": "user", "content": json.dumps(result)})
