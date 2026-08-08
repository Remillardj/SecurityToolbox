"""Tests for the bsot agent command group.

Offline throughout: `run` never reaches the Anthropic API. The "happy path"
and "truncated" tests construct an `AgentRun` directly against a stub
provider (mirroring tests/agent/test_runtime.py) and drive the CLI's
rendering helpers, or monkeypatch `AgentRun`/`AnthropicProvider` so `run`
itself never tries to build a real client. No test writes to ~/.bsot/.
"""

import json
import json as json_lib

from click.testing import CliRunner

from bsot.agent.cli import agent
from bsot.agent.runtime import AgentRun, ToolCall


class StubProvider:
    """Returns a scripted sequence of tool calls, then stops."""

    def __init__(self, script):
        self.script = list(script)

    def next_step(self, messages, tools):
        if self.script:
            return self.script.pop(0)
        return None


class ExplodingProvider:
    """Raises immediately - simulates the run ending in error."""

    def next_step(self, messages, tools):
        raise RuntimeError("simulated provider failure")


class TestList:
    def test_lists_registered_agents(self):
        result = CliRunner().invoke(agent, ["list"])

        assert result.exit_code == 0
        assert "triage" in result.output

    def test_json_output_lists_triage(self):
        result = CliRunner().invoke(agent, ["list", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        names = [a["name"] for a in payload["agents"]]
        assert "triage" in names


class TestRun:
    def test_unknown_agent_exits_2(self):
        result = CliRunner().invoke(agent, ["run", "nope", "--task", "x"])

        assert result.exit_code == 2

    def test_missing_api_key_exits_2(self, monkeypatch, tmp_path):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

        assert result.exit_code == 2
        assert "ANTHROPIC_API_KEY" in result.output

    def test_clean_run_exits_0(self, monkeypatch):
        """A run with no findings and nothing gated exits 0."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            self.stop_reason = "completed"

        monkeypatch.setattr(AgentRun, "execute", fake_execute)

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

        assert result.exit_code == 0

    def test_findings_exit_1(self, monkeypatch):
        """A run whose findings are non-empty exits 1."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            from bsot.agent.provenance import Finding

            self.stop_reason = "completed"
            self.findings.add(Finding(
                claim="binary is unsigned",
                source_command="bsot malware pe s.exe --json",
                exit_code=0,
                confidence="high",
            ))

        monkeypatch.setattr(AgentRun, "execute", fake_execute)

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

        assert result.exit_code == 1
        assert "binary is unsigned" in result.output

    def test_pending_approval_exits_1(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            self.stop_reason = "completed"
            self.pending_approval.append({
                "tool": "bsot_ir_cf_block",
                "command_path": ["ir", "cf", "block"],
                "params": {"ip": "1.2.3.4"},
                "executed": False,
                "reason": "requires human approval",
            })

        monkeypatch.setattr(AgentRun, "execute", fake_execute)

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

        assert result.exit_code == 1
        assert "bsot_ir_cf_block" in result.output

    def test_error_stop_reason_exits_2_even_with_findings(self, monkeypatch):
        """
        A crashed run must exit 2, not 1, even if it recorded findings
        before failing - reporting it as 1 would let a failed run pass for
        a successful triage.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            from bsot.agent.provenance import Finding

            self.findings.add(Finding(
                claim="a", source_command="bsot file hash x", exit_code=0,
            ))
            self.stop_reason = "error"
            self.error = {
                "phase": "provider", "tool": None,
                "exception_type": "RuntimeError", "message": "simulated failure",
            }

        monkeypatch.setattr(AgentRun, "execute", fake_execute)

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

        assert result.exit_code == 2
        assert "ERROR" in result.output

    def test_truncated_run_is_visibly_marked(self, monkeypatch):
        """A run that hits max_iterations must be visibly distinct from a
        completed one in human-readable output."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            self.stop_reason = "max_iterations"

        monkeypatch.setattr(AgentRun, "execute", fake_execute)

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

        assert "TRUNCAT" in result.output.upper()
        # A truncated run with nothing to show exits 1, NOT 0. Exiting 0 would
        # let `if bsot agent run ...; then echo clean; fi` treat an
        # investigation that never finished as a pass - the exact
        # "incomplete reads as clean" failure this design exists to prevent.
        # The banner above says why; the exit code must not contradict it.
        assert result.exit_code == 1

    def test_json_output_parses_and_contains_stop_reason_findings_and_pending(
        self, monkeypatch
    ):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            from bsot.agent.provenance import Finding

            self.stop_reason = "completed"
            self.findings.add(Finding(
                claim="a", source_command="bsot file hash x", exit_code=0,
            ))
            self.pending_approval.append({
                "tool": "bsot_ir_cf_block",
                "command_path": ["ir", "cf", "block"],
                "params": {"ip": "1.2.3.4"},
                "executed": False,
                "reason": "requires human approval",
            })

        monkeypatch.setattr(AgentRun, "execute", fake_execute)

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "x", "--json"])

        payload = json.loads(result.output)
        assert payload["stop_reason"] == "completed"
        assert payload["findings"]["count"] == 1
        assert len(payload["pending_approval"]) == 1

    def test_real_stub_run_reaches_the_cli_end_to_end(self, monkeypatch, tmp_path):
        """
        Exercises the CLI without stubbing execute() itself - only the
        provider is faked, using the same StubProvider pattern as
        tests/agent/test_runtime.py, so the real AgentRun.execute loop runs.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        target = tmp_path / "a.txt"
        target.write_text("x")

        from bsot.agent import runtime as runtime_module

        def fake_provider_init(self, api_key=None, model=runtime_module.MODEL,
                                effort="high", max_tokens=runtime_module.MAX_TOKENS,
                                client=None):
            self.api_key = "test-key"
            self.model = model
            self.effort = effort
            self.max_tokens = max_tokens
            self._client = client

        # A single StubProvider instance, captured once by the lambda below -
        # NOT reconstructed inside it - so its script is consumed across
        # calls. A fresh instance per call would reset the script every
        # time, so next_step would never return None and the loop would run
        # to max_iterations instead of stopping after the one scripted call.
        stub = StubProvider([
            ToolCall(name="bsot_file_hash", params={"files": [str(target)]}),
        ])

        monkeypatch.setattr(
            runtime_module.AnthropicProvider, "__init__", fake_provider_init
        )
        monkeypatch.setattr(
            runtime_module.AnthropicProvider,
            "next_step",
            lambda self, messages, tools: stub.next_step(messages, tools),
        )

        result = CliRunner().invoke(agent, ["run", "triage", "--task", "investigate"])

        assert result.exit_code == 0
        assert "Agent run:" in result.output


class TestRegistration:
    def test_agent_group_is_registered_on_the_root_cli(self):
        from bsot.cli import get_lazy_plugins
        assert "agent" in dict(get_lazy_plugins())


class TestDeclinedRun:
    """
    A run the safety classifiers decline never analyzed the artifact. It must
    not be reportable as a clean verdict - this is the outcome that would most
    directly mislead an analyst about a real sample.
    """

    def _invoke(self, monkeypatch, stop_reason):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        def fake_execute(self, task):
            self.stop_reason = stop_reason

        monkeypatch.setattr(AgentRun, "execute", fake_execute)
        return CliRunner().invoke(agent, ["run", "triage", "--task", "x"])

    def test_refusal_exits_2_and_says_it_was_never_analyzed(self, monkeypatch):
        result = self._invoke(monkeypatch, "refusal")

        assert result.exit_code == 2
        assert "DECLINED" in result.output.upper()
        assert "never analyzed" in result.output.lower()

    def test_refusal_never_reports_completed(self, monkeypatch):
        result = self._invoke(monkeypatch, "refusal")

        assert "status: completed" not in result.output.lower()

    def test_token_truncation_is_marked_and_does_not_exit_zero(self, monkeypatch):
        result = self._invoke(monkeypatch, "max_tokens")

        assert result.exit_code == 1
        assert "TRUNCAT" in result.output.upper()


def _catalogue():
    result = CliRunner().invoke(agent, ["catalogue", "--json"])
    assert result.exit_code == 0, result.output
    return json_lib.loads(result.output)


def test_catalogue_emits_pinned_version_and_commands():
    payload = _catalogue()
    assert payload["catalogue_version"] == 1
    assert isinstance(payload["bsot_version"], str)
    assert len(payload["commands"]) > 50


def test_every_entry_carries_dispatch_metadata_and_a_tier():
    """SEC_MCP rebuilds argv from `params` and gates on `tier`; an entry
    missing either is unusable and must never ship."""
    required = {
        "name", "path", "description", "input_schema",
        "params", "supports_json", "tier",
    }
    for entry in _catalogue()["commands"]:
        assert required <= set(entry), entry.get("name")
        assert entry["tier"] in {
            "read_only", "case_write", "taint_gated", "external_mutation"
        }


def test_underscore_dispatch_keys_are_promoted_not_leaked():
    """bridge.py hides these from a model; this consumer is a program, so
    they are promoted to real keys and the underscore form is gone."""
    entry = next(
        e for e in _catalogue()["commands"] if e["name"] == "bsot_intel_enrich"
    )
    assert entry["path"] == ["intel", "enrich"]
    assert not any(k.startswith("_") for k in entry)


def test_a_known_read_only_command_is_tiered_read_only():
    entry = next(
        e for e in _catalogue()["commands"] if e["name"] == "bsot_data_decode"
    )
    assert entry["tier"] == "read_only"


def test_a_known_gated_command_is_not_read_only():
    """network ports is EXTERNAL_MUTATION; if this ever reads read_only the
    tier export is wired to the wrong function."""
    entry = next(
        e for e in _catalogue()["commands"] if e["name"] == "bsot_network_ports"
    )
    assert entry["tier"] == "external_mutation"


def test_the_agent_group_is_not_in_its_own_catalogue():
    names = {e["name"] for e in _catalogue()["commands"]}
    assert not any(n.startswith("bsot_agent") for n in names)
