"""Tests for tool tiering and the approval gate."""

from bsot.agent.safety import Tier, tier_for


class TestTiering:
    def test_read_only_commands(self):
        assert tier_for(["file", "hash"]) is Tier.READ_ONLY
        assert tier_for(["intel", "enrich"]) is Tier.READ_ONLY
        assert tier_for(["logs", "analyze"]) is Tier.READ_ONLY

    def test_case_writes(self):
        assert tier_for(["case", "add"]) is Tier.CASE_WRITE
        assert tier_for(["case", "note"]) is Tier.CASE_WRITE

    def test_cloudflare_containment_is_mutating(self):
        """These change production firewall rules."""
        assert tier_for(["ir", "cf", "block"]) is Tier.EXTERNAL_MUTATION
        assert tier_for(["ir", "cf", "bulk-block"]) is Tier.EXTERNAL_MUTATION
        assert tier_for(["ir", "cf", "unblock"]) is Tier.EXTERNAL_MUTATION
        assert tier_for(["ir", "contain"]) is Tier.EXTERNAL_MUTATION

    def test_unknown_command_defaults_to_mutating(self):
        """Fail closed: an unclassified command is treated as dangerous."""
        assert tier_for(["some", "future", "command"]) is Tier.EXTERNAL_MUTATION

    def test_malware_submit_is_mutating(self):
        """Uploading a sample to a third party is not read-only."""
        assert tier_for(["malware", "submit"]) is Tier.EXTERNAL_MUTATION
