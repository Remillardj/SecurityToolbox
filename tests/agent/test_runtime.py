"""Tests for the agent loop, against a stubbed provider.

The suite must stay fast, offline, and free, so no test here reaches the API.
"""

import json

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
