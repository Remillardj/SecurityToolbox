"""Tests for the agent loop, against a stubbed provider.

The suite must stay fast, offline, and free, so no test here reaches the API.
"""

import copy
import json

import pytest

from bsot.agent.runtime import AgentRun, ToolCall
from bsot.agent.safety import UNTRUSTED_TAG_PREFIX


class StubProvider:
    """Returns a scripted sequence of tool calls, then stops."""

    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    def next_step(self, messages, tools):
        self.seen.append(messages)
        if self.script:
            return self.script.pop(0)
        return None


class CapturingProvider:
    """Like StubProvider, but also records the `tools` argument it was given."""

    def __init__(self, script):
        self.script = list(script)
        self.tools_seen = None

    def next_step(self, messages, tools):
        self.tools_seen = tools
        if self.script:
            return self.script.pop(0)
        return None


class TestLoop:
    def test_runs_until_the_provider_stops(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("investigate this")

        assert len(run.transcript) == 1

    def test_read_only_calls_are_not_gated(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert run.pending_approval == []

    def test_mutating_call_is_gated_not_executed(self):
        provider = StubProvider([
            ToolCall(name="bsot_ir_cf_block", params={"ip": "1.2.3.4"}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert len(run.pending_approval) == 1
        assert run.transcript[0]["executed"] is False

    def test_tool_output_is_framed_as_untrusted(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        # ADAPTED from the plan: Task 4's hardening replaced the fixed
        # "untrusted_data" tag with a per-call nonce of the form
        # "bsot-untrusted-<16 hex>" (see safety.UNTRUSTED_TAG_PREFIX /
        # frame_untrusted), so the literal string "untrusted_data" no longer
        # appears anywhere in the envelope. This asserts on the real
        # boundary marker instead - still proving the output was framed,
        # just against the envelope that actually ships.
        assert UNTRUSTED_TAG_PREFIX in run.transcript[0]["framed_output"]

    def test_run_becomes_tainted_after_reading_output(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert run.state.tainted is True

    def test_iteration_cap_is_enforced(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        call = ToolCall(name="bsot_file_hash", params={"files": [str(target)]})
        provider = StubProvider([call] * 100)
        run = AgentRun(agent="triage", provider=provider, max_iterations=3)

        run.execute("go")

        assert len(run.transcript) == 3


class TestRecordFinding:
    """
    record_finding is a hand-written tool (bsot.agent.provenance), not a CLI
    command - it has no entry in build_catalogue() and must be dispatched by
    name before the catalogue lookup. Without this dispatch, a model's
    record_finding call falls through to "unknown tool" and every finding is
    silently lost.
    """

    def test_dispatches_by_name_and_records_a_finding(self):
        provider = StubProvider([
            ToolCall(name="record_finding", params={
                "claim": "binary is unsigned",
                "source_command": "bsot malware pe sample.exe --json",
                "exit_code": 0,
                "evidence": "authentihash_present: false",
                "confidence": "high",
            }),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert len(run.findings) == 1
        assert run.findings.findings[0].claim == "binary is unsigned"

    def test_does_not_taint_the_run(self):
        """record_finding's result is our own dict, not command output."""
        provider = StubProvider([
            ToolCall(name="record_finding", params={
                "claim": "x", "source_command": "bsot file hash a", "exit_code": 0,
            }),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert run.state.tainted is False
        assert run.state.untrusted_sources == []

    def test_result_is_not_framed_as_untrusted(self):
        provider = StubProvider([
            ToolCall(name="record_finding", params={
                "claim": "x", "source_command": "bsot file hash a", "exit_code": 0,
            }),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        entry = run.transcript[0]
        assert "framed_output" not in entry
        assert UNTRUSTED_TAG_PREFIX not in json.dumps(entry)

    def test_failed_call_is_tracked_not_raised(self):
        """A blank source_command fails Finding's own validation."""
        provider = StubProvider([
            ToolCall(name="record_finding", params={
                "claim": "the host is compromised",
                "source_command": "",
                "exit_code": 0,
            }),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")  # must not raise

        assert len(run.findings) == 0
        assert len(run.failed_findings) == 1

    def test_two_failed_attempts_are_both_tracked(self):
        """A model that fails validation twice and moves on must not under-report."""
        provider = StubProvider([
            ToolCall(name="record_finding", params={
                "claim": "a", "source_command": "", "exit_code": 0,
            }),
            ToolCall(name="record_finding", params={
                "claim": "b", "source_command": "bsot file hash a", "exit_code": 0,
                "confidence": "certain",
            }),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert len(run.findings) == 0
        assert len(run.failed_findings) == 2

    def test_tool_is_exposed_to_the_provider(self):
        """A real provider must be able to see the tool in order to call it."""
        provider = CapturingProvider([])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        names = [tool["name"] for tool in provider.tools_seen]
        assert "record_finding" in names


class TestEmptyOutputFraming:
    """
    On timeout, missing binary, or a signal-killed child, stdout and stderr
    can both be empty while the only diagnostic lives in CommandResult.error.
    Framing an empty block there would tell the model nothing went wrong.
    """

    def test_empty_streams_fall_back_to_the_error_diagnostic(self, tmp_path, monkeypatch):
        import bsot.agent.executor as executor_module

        script = tmp_path / "silent_fail.py"
        script.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(3)\n")
        script.chmod(0o755)
        monkeypatch.setattr(executor_module, "_resolve_binary", lambda: str(script))

        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")  # must not raise, and must not frame an empty block

        entry = run.transcript[0]
        assert entry["exit_code"] == 3
        assert "no stdout or stderr" in entry["framed_output"]


class TestTaintChangesBehavior:
    """
    Proves taint actually changes what runs, end to end: the same call that
    auto-runs clean is gated once the run has read untrusted output.
    """

    def test_tainted_run_gates_a_case_write_call_that_was_allowed_clean(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            # First call: a real read-only command, which taints the run
            # (all executed CLI output is untrusted by design - see
            # safety.RunState).
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
            # Second call: CASE_WRITE, auto-runnable on a clean run, but
            # must now be gated because the run is tainted.
            ToolCall(name="bsot_case_note", params={"text": "note"}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert run.state.tainted is True
        assert len(run.transcript) == 2
        assert run.transcript[0]["executed"] is True
        assert run.transcript[1]["executed"] is False
        assert len(run.pending_approval) == 1
        assert run.pending_approval[0]["tool"] == "bsot_case_note"


class SnapshotProvider:
    """
    Like StubProvider, but records a length-accurate snapshot of `messages`
    at each call.

    StubProvider.next_step stores a live reference to the same `messages`
    list `AgentRun.execute` mutates in place - by the end of a run, every
    entry already appended to `self.seen` points at the SAME, fully-grown
    list object, so comparing `len(seen[0])` to `len(seen[1])` after the run
    finishes would trivially compare a list to itself. Copying at call time
    (`list(messages)`) freezes each turn's length instead.
    """

    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    def next_step(self, messages, tools):
        self.seen.append(list(messages))
        if self.script:
            return self.script.pop(0)
        return None


class TestGatedAndUnknownToolFeedback:
    """
    Regression coverage: a gated or unknown-tool call must still produce a
    message back to the model, same as every other tool call. Without this,
    the model either retries the same gated call until max_iterations burns
    out - exactly the loop Task 9's triage prompt tells it not to do - or
    gets no chance to correct a typoed tool name.
    """

    def test_gated_call_grows_the_message_list_the_provider_sees(self):
        call = ToolCall(name="bsot_ir_cf_block", params={"ip": "1.2.3.4"})
        # Scripted twice so next_step is invoked a second time, letting us
        # compare the messages list the provider saw on turn 1 vs. turn 2.
        provider = SnapshotProvider([call, call])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert len(provider.seen) >= 2
        assert len(provider.seen[1]) > len(provider.seen[0])
        feedback = provider.seen[1][-1]
        assert feedback["role"] == "user"
        assert "approval" in feedback["content"].lower()

    def test_unknown_tool_call_grows_the_message_list_the_provider_sees(self):
        call = ToolCall(name="bsot_not_a_real_tool", params={})
        provider = SnapshotProvider([call, call])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert len(provider.seen) >= 2
        assert len(provider.seen[1]) > len(provider.seen[0])
        feedback = provider.seen[1][-1]
        assert feedback["role"] == "user"
        assert "not a recognized tool" in feedback["content"].lower()

    def test_gated_call_still_appears_in_pending_approval_as_not_executed(self):
        """Proves the feedback message didn't alter gating behavior."""
        call = ToolCall(name="bsot_ir_cf_block", params={"ip": "1.2.3.4"})
        provider = StubProvider([call])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        assert len(run.pending_approval) == 1
        assert run.pending_approval[0]["executed"] is False
        assert run.transcript[0]["executed"] is False

    def test_gated_feedback_does_not_taint_or_get_framed_as_untrusted(self):
        call = ToolCall(name="bsot_ir_cf_block", params={"ip": "1.2.3.4"})
        provider = StubProvider([call])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")

        # Only the gated call ran (nothing else in the script), so if
        # taint tracking correctly ignored the feedback message, the run
        # is still clean.
        assert run.state.tainted is False
        assert run.state.untrusted_sources == []

        feedback = provider.seen[-1][-1]
        assert feedback["role"] == "user"
        assert UNTRUSTED_TAG_PREFIX not in feedback["content"]


class TestAnthropicProvider:
    def test_requires_an_api_key(self, monkeypatch):
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            AnthropicProvider(api_key=None)

    def test_defers_tool_loading(self, monkeypatch):
        """70+ schemas in context would be wasteful; they load on demand."""
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        provider = AnthropicProvider()
        payload = provider.build_tools([
            {"name": "bsot_file_hash", "description": "d",
             "input_schema": {"type": "object", "properties": {}, "required": []},
             "_command_path": ["file", "hash"],
             "_params": {"files": {"kind": "argument", "is_flag": False,
                                    "multiple": False, "nargs": -1}},
             "_supports_json": True},
        ])

        # TIGHTENED from the plan: the bridge also emits `_params` and
        # `_supports_json` (see bridge.command_to_schema), not just
        # `_command_path` - asserting on one key would let those two leak to
        # the model undetected. No key beginning with "_" may survive.
        assert payload[0]["defer_loading"] is True
        assert not any(key.startswith("_") for key in payload[0])

    def test_includes_the_tool_search_tool(self, monkeypatch):
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        provider = AnthropicProvider()
        payload = provider.build_tools([])

        assert any(t.get("type", "").startswith("tool_search") for t in payload)

    def test_record_finding_is_not_deferred(self, monkeypatch):
        """
        Design spec (2026-08-02-bsot-agents-design.md, "Do not load 72 tools
        into context"): record_finding is one of the handful of tools that
        stay loaded because nearly every run needs them - unlike every CLI
        command tool, it must NOT get `defer_loading`.
        """
        from bsot.agent.provenance import build_record_finding_tool
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        provider = AnthropicProvider()
        # Mirrors AgentRun.tools, which already appends
        # build_record_finding_tool() to the catalogue before the provider
        # ever sees it (see AgentRun.__init__).
        payload = provider.build_tools([build_record_finding_tool()])

        matches = [t for t in payload if t["name"] == "record_finding"]
        assert len(matches) == 1
        assert "defer_loading" not in matches[0]

    def test_record_finding_is_present_even_if_the_caller_omitted_it(self, monkeypatch):
        """build_tools guarantees record_finding reaches the model either way."""
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        provider = AnthropicProvider()
        payload = provider.build_tools([])

        matches = [t for t in payload if t["name"] == "record_finding"]
        assert len(matches) == 1

    def test_record_finding_is_never_duplicated(self, monkeypatch):
        """
        AgentRun.tools already contains record_finding (catalogue +
        [build_record_finding_tool()]) by the time build_tools sees it -
        build_tools must not also append its own copy on top of that one.
        """
        from bsot.agent.provenance import build_record_finding_tool
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        provider = AnthropicProvider()
        payload = provider.build_tools([
            {"name": "bsot_file_hash", "description": "d",
             "input_schema": {"type": "object", "properties": {}, "required": []},
             "_command_path": ["file", "hash"], "_params": {}, "_supports_json": True},
            build_record_finding_tool(),
        ])

        matches = [t for t in payload if t["name"] == "record_finding"]
        assert len(matches) == 1

    def test_does_not_mutate_the_input_catalogue(self, monkeypatch):
        """
        The catalogue is reused across turns, and build_record_finding_tool()
        returning a fresh copy on every call is by design (see
        provenance.py) - build_tools must not undo that by mutating the
        dicts it was handed in place.
        """
        from bsot.agent.runtime import AnthropicProvider

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        provider = AnthropicProvider()
        tool = {
            "name": "bsot_file_hash", "description": "d",
            "input_schema": {"type": "object", "properties": {}, "required": []},
            "_command_path": ["file", "hash"], "_params": {}, "_supports_json": True,
        }
        before = copy.deepcopy(tool)
        catalogue = [tool]

        provider.build_tools(catalogue)

        assert catalogue == [before]
        assert tool == before


class ImmediatelyExplodingProvider:
    """Raises on every call - simulates an API failure before any call is made."""

    def next_step(self, messages, tools):
        raise RuntimeError("provider exploded")


class ExplodesOnSecondCallProvider:
    """
    Returns one scripted call, then raises - simulates a routine mid-run API
    failure (rate limit, network blip, timeout, overloaded error) on the
    turn AFTER the model has already made real progress.
    """

    def __init__(self, first_call):
        self.first_call = first_call
        self.calls = 0

    def next_step(self, messages, tools):
        self.calls += 1
        if self.calls == 1:
            return self.first_call
        raise RuntimeError("provider exploded on turn 2 (e.g. a 429)")


class TestProviderExceptionSurvival:
    """
    In production, `next_step` calls the Claude API - a rate limit, a
    network blip, a timeout, or an overloaded error are all routine on a
    long run. Before this fix, any of those propagated straight out of
    execute(), so the caller (Task 12's CLI) never reached the code that
    prints findings: a run that had already recorded twenty findings and
    then hit a 429 on turn twenty-one reported nothing at all.
    """

    def test_provider_exception_on_first_call_ends_the_run_cleanly(self):
        run = AgentRun(agent="triage", provider=ImmediatelyExplodingProvider())

        run.execute("go")  # must not raise

        assert run.error is not None
        assert run.error["phase"] == "provider"
        assert run.error["tool"] is None
        assert run.error["exception_type"] == "RuntimeError"
        assert "provider exploded" in run.error["message"]

        assert len(run.transcript) == 1
        assert run.transcript[0]["executed"] is False
        assert "RuntimeError" in run.transcript[0]["error"]

    def test_findings_and_transcript_survive_a_later_provider_exception(self):
        """
        The scenario the fix exists for: a run that already recorded a real
        finding must not lose it just because a later call to the provider
        blows up. This is the test that proves the loss scenario is closed.
        """
        first_call = ToolCall(name="record_finding", params={
            "claim": "binary is unsigned",
            "source_command": "bsot malware pe sample.exe --json",
            "exit_code": 0,
        })
        provider = ExplodesOnSecondCallProvider(first_call)
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")  # must not raise

        # The first call's finding and transcript entry survive intact.
        assert len(run.findings) == 1
        assert run.findings.findings[0].claim == "binary is unsigned"
        assert len(run.transcript) == 2
        assert run.transcript[0]["recorded"] is True

        # The second call's failure is visible, not silently swallowed.
        assert run.transcript[1]["executed"] is False
        assert "RuntimeError" in run.transcript[1]["error"]
        assert run.error is not None
        assert run.error["phase"] == "provider"
        assert run.error["exception_type"] == "RuntimeError"

    def test_does_not_catch_keyboard_interrupt(self):
        class InterruptingProvider:
            def next_step(self, messages, tools):
                raise KeyboardInterrupt()

        run = AgentRun(agent="triage", provider=InterruptingProvider())

        with pytest.raises(KeyboardInterrupt):
            run.execute("go")

        assert run.error is None

    def test_does_not_catch_system_exit(self):
        class ExitingProvider:
            def next_step(self, messages, tools):
                raise SystemExit(1)

        run = AgentRun(agent="triage", provider=ExitingProvider())

        with pytest.raises(SystemExit):
            run.execute("go")

        assert run.error is None

    def test_tool_execution_exception_is_caught_and_recorded(self, monkeypatch):
        """Defensive coverage: the tool-execution path, not just the provider."""
        import bsot.agent.runtime as runtime_module

        def _boom(*args, **kwargs):
            raise ValueError("run_command exploded")

        monkeypatch.setattr(runtime_module, "run_command", _boom)

        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": []}),
        ])
        run = AgentRun(agent="triage", provider=provider)

        run.execute("go")  # must not raise

        assert run.error is not None
        assert run.error["phase"] == "tool_execution"
        assert run.error["tool"] == "bsot_file_hash"
        assert run.error["exception_type"] == "ValueError"
        assert len(run.transcript) == 1
        assert run.transcript[0]["executed"] is False


class TestStopReason:
    """
    `self.stop_reason` distinguishes "the provider decided it was done"
    from "the loop hit max_iterations while the provider still had more to
    say" - without it, both look identical to a caller (same transcript
    shape, same self.error), and a truncated investigation (three findings
    because the cap cut off a four-call run) can be reported as a
    completed one.
    """

    def test_provider_stopping_early_is_completed(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        provider = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])
        run = AgentRun(agent="triage", provider=provider, max_iterations=10)

        run.execute("go")

        assert run.stop_reason == "completed"
        assert run.error is None

    def test_provider_never_stopping_is_max_iterations(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("x")
        call = ToolCall(name="bsot_file_hash", params={"files": [str(target)]})
        provider = StubProvider([call] * 100)
        run = AgentRun(agent="triage", provider=provider, max_iterations=3)

        run.execute("go")

        assert run.stop_reason == "max_iterations"
        assert len(run.transcript) == 3

    def test_stopping_exactly_on_the_last_permitted_call_is_completed_not_truncated(
        self, tmp_path
    ):
        """
        The boundary that's easy to get backwards: the provider returns
        real calls for iterations 1..N-1, then None on the Nth (last
        permitted) call, with max_iterations=N. The full budget was used,
        but the provider genuinely finished - this must read as
        "completed", not "max_iterations", or every well-behaved run that
        happens to use its whole budget would get a false truncation
        warning.
        """
        target = tmp_path / "a.txt"
        target.write_text("x")
        call = ToolCall(name="bsot_file_hash", params={"files": [str(target)]})
        # max_iterations=3: two real calls, then None on the 3rd (last
        # permitted) request.
        provider = StubProvider([call, call, None])
        run = AgentRun(agent="triage", provider=provider, max_iterations=3)

        run.execute("go")

        assert run.stop_reason == "completed"
        assert len(run.transcript) == 2

    def test_error_path_sets_stop_reason_to_error(self):
        run = AgentRun(agent="triage", provider=ImmediatelyExplodingProvider())

        run.execute("go")

        assert run.stop_reason == "error"
        assert run.error is not None
        assert run.error["phase"] == "provider"

    def test_stop_reason_is_none_before_execute_runs(self):
        run = AgentRun(agent="triage", provider=StubProvider([]))

        assert run.stop_reason is None
