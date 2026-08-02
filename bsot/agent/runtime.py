"""
The agent loop.

This is the only module aware of the execution model. Everything it depends
on - the bridge, safety, provenance, budget - is provider-agnostic, so
replacing this file swaps local execution for hosted without touching the
rest (Task 11 appends an AnthropicProvider to this same file rather than
introducing a second provider-aware module).

Corrections vs. the plan's original skeleton, all load-bearing:

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
3. A gated or unknown-tool call must still produce a message back to the
   model, same as every other tool call - otherwise the model either
   retries the same gated call until `max_iterations` burns out (exactly
   the loop Task 9's triage prompt tells it not to do), or gets no chance
   to correct a typoed tool name. `_gated_feedback` and
   `_unknown_tool_feedback` build that text; neither goes through
   `frame_untrusted` or taints the run, because both are our own text, not
   command output an adversary-controlled artifact could have influenced.
4. `execute()` must not let an exception from `provider.next_step` (or,
   defensively, from the tool-execution / record_finding paths) propagate.
   In production `next_step` calls the Claude API, so a rate limit, a
   network blip, a timeout, or an overloaded error is routine on a long
   run - and if it escapes `execute()`, the caller (Task 12's CLI) never
   reaches the code that prints findings, so every finding already
   recorded in the run is lost with it. `Exception` is caught (never
   `KeyboardInterrupt`/`SystemExit`, which are not `Exception` subclasses
   anyway), recorded on `self.error` and in the transcript, and the loop
   stops - no retry, no silent swallow.
5. Hitting `max_iterations` must be distinguishable from the provider
   genuinely finishing - otherwise a truncated run (three findings because
   the cap cut off a four-call investigation) and a completed one look
   identical to a caller, and an incomplete investigation can be reported
   as a clean one. `self.stop_reason` records which of the two happened;
   see `execute()`'s `for ... else` for how the "provider used its very
   last permitted call to say it was done" case is kept out of
   "max_iterations" (that would be a false truncation warning on every
   well-behaved run that uses its full budget).
"""

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .bridge import build_catalogue
from .definitions import get_definition
from .executor import CommandResult, run_command
from .provenance import FindingLog, build_record_finding_tool, record_finding
from .safety import RunState, Tier, frame_untrusted, requires_approval, tier_for


@dataclass
class ToolCall:
    """One tool invocation requested by the model."""

    name: str
    params: Dict[str, Any] = field(default_factory=dict)


# Provider stop reasons meaning the run did NOT finish its work, mapped to the
# run's own stop_reason. Anything else - end_turn, or a provider that doesn't
# report one - means the agent genuinely stopped on its own.
_INCOMPLETE_PROVIDER_REASONS = {
    "refusal": "refusal",
    "max_tokens": "max_tokens",
}


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


def _gated_feedback(call: "ToolCall", path: List[str], tier: Tier) -> str:
    """
    Text fed back to the model when a call is gated for human approval.

    Deliberately echoes Task 9's triage prompt ("do not retry it and do not
    hunt for a workaround - note what you wanted to run and why as part of
    your findings, and keep going") so the runtime's behavior and the
    prompt's instructions agree, rather than the model having read guidance
    that the loop never actually followed through on.
    """
    command_name = "bsot " + " ".join(path)
    return (
        f"Tool call '{call.name}' ({command_name}) was NOT executed. It is "
        f"tier {tier.value}, which requires a human to approve it before it "
        "can run; it has been queued for approval. Do not retry this call "
        "and do not hunt for a workaround. Note what you wanted to run and "
        "why as part of your findings, and keep going with what is still "
        "available to you."
    )


def _unknown_tool_feedback(call: "ToolCall") -> str:
    """Text fed back to the model when it calls a tool name that doesn't exist."""
    return (
        f"Tool call '{call.name}' was NOT executed: this is not a "
        "recognized tool name (it is not in the tool catalogue and is not "
        "record_finding). Check the spelling against the tools you were "
        "given and, if you meant a different tool, call that one instead."
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
        # Set once execute() catches an unexpected exception (provider,
        # tool-execution, or record_finding) and ends the run early. `None`
        # means the run completed (or hasn't run yet) without one. Shape:
        # {"phase": str, "tool": Optional[str], "exception_type": str,
        #  "message": str} - Task 12 reads this to render the failure.
        # `tool` is None specifically for a provider-phase failure (the
        # exception happened before any call was obtained, so there is no
        # tool name yet) - a consumer must not assume "tool" is always a
        # string.
        self.error: Optional[Dict[str, Any]] = None
        # How the loop ended - set exactly once, at the very end of
        # execute(). One of "completed" (provider returned None),
        # "max_iterations" (the loop exhausted its budget while the
        # provider still had more to say), or "error" (see self.error).
        # `None` until execute() has run. Task 12 renders this so a
        # truncated investigation is never reported as a finished one.
        self.stop_reason: Optional[str] = None

    def execute(self, task: str) -> None:
        """Run the loop until the provider stops or the cap is reached."""
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.definition.system_prompt},
            {"role": "user", "content": task},
        ]

        # The `else` on this `for` only runs if the loop exhausts
        # `max_iterations` without ever hitting a `break` below - i.e. the
        # provider was still returning real calls on its last permitted
        # turn. Both other ways the loop can end (`call is None`, or an
        # exception) `break` after setting `self.stop_reason` themselves,
        # so they never reach the `else`. This is what keeps "the provider
        # used its very last call to say it was done" out of
        # "max_iterations": that path breaks with "completed" before the
        # loop ever gets a chance to exhaust naturally.
        for _ in range(self.max_iterations):
            try:
                call = self.provider.next_step(messages, self.tools)
            except Exception as exc:  # noqa: BLE001 - see module docstring, point 4
                self._record_failure(phase="provider", tool=None, exc=exc)
                self.stop_reason = "error"
                break

            if call is None:
                # A provider can stop for reasons that are NOT "the agent
                # finished": the request was declined by safety classifiers,
                # or the response hit its token ceiling mid-turn. Both come
                # back as "no tool call" and would otherwise be reported as a
                # clean, completed run - so a declined malware triage would
                # read exactly like "we looked and found nothing". Providers
                # that can distinguish these expose `last_stop_reason`;
                # a provider without it (a test stub) is treated as completed.
                self.stop_reason = _INCOMPLETE_PROVIDER_REASONS.get(
                    getattr(self.provider, "last_stop_reason", None), "completed"
                )
                break

            try:
                if call.name == "record_finding":
                    self._dispatch_record_finding(call, messages)
                    continue

                tool = _tool_for(call.name, self.catalogue)
                if tool is None:
                    self.transcript.append({
                        "tool": call.name, "executed": False,
                        "error": "unknown tool",
                    })
                    messages.append(
                        {"role": "user", "content": _unknown_tool_feedback(call)}
                    )
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
                    messages.append({
                        "role": "user",
                        "content": _gated_feedback(call, path, tier_for(path)),
                    })
                    continue

                # The runtime already holds the catalogue entry for this
                # tool, so its param metadata and JSON support are passed
                # straight through rather than making the executor
                # re-look them up (and, for any path outside the
                # catalogue, this also bypasses the executor's own
                # catalogue-refusal guard - correct here because `tool`
                # above already proves this path came from the catalogue).
                result = run_command(
                    path,
                    call.params,
                    param_meta=tool["_params"],
                    supports_json=tool["_supports_json"],
                )
                framed = frame_untrusted(
                    _content_for_framing(result), source=result.command
                )
                self.state.record_untrusted(result.command)

                self.transcript.append({
                    "tool": call.name,
                    "command": result.command,
                    "exit_code": result.exit_code,
                    "executed": True,
                    "framed_output": framed,
                })
                messages.append({"role": "user", "content": framed})
            except Exception as exc:  # noqa: BLE001 - see module docstring, point 4
                phase = "record_finding" if call.name == "record_finding" else "tool_execution"
                self._record_failure(phase=phase, tool=call.name, exc=exc)
                self.stop_reason = "error"
                break
        else:
            # Only reached when the `for` ran out of iterations without a
            # `break` - the provider was still handing back real calls on
            # the last permitted turn, so the cap (not the provider) is
            # what ended the run.
            self.stop_reason = "max_iterations"

    def _record_failure(self, phase: str, tool: Optional[str], exc: Exception) -> None:
        """
        Record an unexpected exception and let the run end cleanly instead
        of propagating it out of `execute()`.

        Findings, transcript entries, and the pending-approval queue
        recorded before the failure are left exactly as they were - the
        whole point is that a routine provider hiccup (rate limit, network
        blip, timeout, overloaded error) partway through a long run must
        not erase everything the run already found. No retry is attempted
        here; that policy is out of scope for the runtime loop.
        """
        self.error = {
            "phase": phase,
            "tool": tool,
            "exception_type": type(exc).__name__,
            "message": str(exc),
        }
        self.transcript.append({
            "tool": tool,
            "executed": False,
            "error": f"{phase} failed: {type(exc).__name__}: {exc}",
            "phase": phase,
        })

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


MODEL = "claude-opus-5"
# Thinking is on by default on this model and max_tokens caps thinking plus
# response text together, so a tight ceiling truncates mid-turn across a long
# tool-calling run. Sized for headroom rather than the non-streaming default.
MAX_TOKENS = 32000
TOOL_SEARCH = {
    "type": "tool_search_tool_bm25_20251119",
    "name": "tool_search_tool_bm25",
}


class AnthropicProvider:
    """
    Talks to the Claude API.

    Tool schemas are declared deferred and paired with the tool-search tool:
    carrying 70+ security tools in context on every turn would be expensive and
    would crowd out the evidence the agent is meant to reason about.

    record_finding is the deliberate exception (design spec, "Do not load 72
    tools into context"): nearly every run needs it, so build_tools below
    keeps it loaded rather than deferred.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = MODEL,
        effort: str = "high",
        max_tokens: int = MAX_TOKENS,
        client: Any = None,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Run 'bsot config check' to see "
                "which keys are configured."
            )
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        # The API's stop_reason from the most recent turn. The loop reads this
        # when next_step returns no tool call, so that "the classifiers
        # declined" and "the response ran out of tokens" are not both reported
        # as a completed run.
        self.last_stop_reason: Optional[str] = None
        # Built on first use, not here: constructing a client at import/init
        # time would make the SDK a hard dependency of `bsot agent list`,
        # which needs no API at all. `client` is injectable so the tests can
        # assert on the request without reaching the network.
        self._client = client

    def build_tools(self, catalogue: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Strip internal keys and mark every command tool deferred.

        record_finding is excluded from deferral, not just excluded from key
        stripping: `AgentRun.tools` already appends `build_record_finding_tool()`
        to the catalogue (see `AgentRun.__init__`), so an entry named
        "record_finding" may already be present in `catalogue` by the time this
        runs. That entry is skipped here rather than stripped-and-deferred like
        everything else, and a fresh, canonical copy is appended once at the
        end instead. This keeps the result correct - present exactly once,
        never deferred - whether the caller passes the raw command catalogue,
        `AgentRun.tools` (which already contains it), or something in between.
        The dict comprehension below builds a new dict per tool rather than
        mutating in place, so neither this skip-and-append nor the key
        stripping touches the caller's original list or dicts.
        """
        tools: List[Dict[str, Any]] = []
        for tool in catalogue:
            if tool.get("name") == "record_finding":
                continue
            payload = {k: v for k, v in tool.items() if not k.startswith("_")}
            payload["defer_loading"] = True
            tools.append(payload)
        # record_finding and the tool-search tool are both left undeferred on
        # purpose. Beyond the design spec's reasoning, the API rejects a
        # request in which every tool is deferred, so this is also what keeps
        # the request valid at all.
        tools.append(build_record_finding_tool())
        tools.append(TOOL_SEARCH)
        return tools

    def _get_client(self) -> Any:
        """
        Build the SDK client on first use.

        `anthropic` is an optional extra for this package (see pyproject), so
        the import lives here rather than at module scope: `bsot agent list`
        and every offline test must work without it installed.
        """
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError(
                    "anthropic library not installed. "
                    "Install with: pip install anthropic"
                ) from exc
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def _build_request(
        self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Shape one API request.

        The loop seeds its conversation with a leading `{"role": "system"}`
        entry, but `system` is a top-level parameter on this API, not a
        message role - an entry in that position is rejected. It is peeled off
        here rather than in the loop so the loop stays provider-agnostic.

        No `temperature`, `top_p`, `top_k`, or `budget_tokens`: all four are
        rejected on this model family. Thinking depth is set through effort.
        """
        system: Optional[str] = None
        conversation = list(messages)
        if conversation and conversation[0].get("role") == "system":
            system = conversation.pop(0)["content"]

        request: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": conversation,
            "tools": self.build_tools(tools),
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": self.effort},
        }
        if system is not None:
            request["system"] = system
        return request

    def next_step(
        self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Optional[ToolCall]:
        """
        Ask the model what to do next.

        Returns the first tool call the model requests, or None when it stops
        - including when safety classifiers decline the request, which arrives
        as a normal response with `stop_reason == "refusal"` rather than an
        error, and whose `content` may be empty.
        """
        response = self._get_client().messages.create(
            **self._build_request(messages, tools)
        )
        self.last_stop_reason = getattr(response, "stop_reason", None)

        if self.last_stop_reason == "refusal":
            return None

        for block in getattr(response, "content", None) or []:
            if getattr(block, "type", None) == "tool_use":
                return ToolCall(name=block.name, params=dict(block.input or {}))
        return None
