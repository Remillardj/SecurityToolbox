"""Tests for agent definitions."""

from bsot.agent.definitions import get_definition, list_definitions


class TestRegistry:
    def test_triage_is_registered(self):
        assert "triage" in list_definitions()

    def test_unknown_name_raises(self):
        import pytest

        with pytest.raises(KeyError):
            get_definition("no-such-agent")


class TestTriage:
    def test_has_a_system_prompt(self):
        assert len(get_definition("triage").system_prompt) > 200

    def test_prompt_forbids_unsourced_claims(self):
        prompt = get_definition("triage").system_prompt.lower()

        assert "record_finding" in prompt

    def test_prompt_names_the_untrusted_input_risk(self):
        prompt = get_definition("triage").system_prompt.lower()

        assert "untrusted" in prompt

    def test_uses_high_effort(self):
        """Triage is agentic and long-horizon."""
        assert get_definition("triage").effort in ("high", "xhigh")
