"""Tests for tool tiering and the approval gate."""

import pytest

from bsot.agent.bridge import build_catalogue
from bsot.agent.safety import (
    Tier,
    _CASE_WRITE,
    _EXTERNAL_MUTATION,
    _READ_ONLY,
    _TAINT_GATED,
    requires_approval,
    tier_for,
)


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


_ALL_TIER_SETS = (_READ_ONLY, _CASE_WRITE, _TAINT_GATED, _EXTERNAL_MUTATION)


class TestCompleteness:
    """
    The whole point of per-command classification is that nothing rides in
    on a group whitelist by accident. This is the mechanism that makes that
    true: every tool the bridge currently generates must be explicitly
    placed in exactly one of the four tier sets. A new CLI command breaks
    this test until a human classifies it deliberately - that's the
    guarantee the safety.py module docstring promises, made real.
    """

    def test_every_catalogue_command_is_classified_exactly_once(self):
        catalogue = build_catalogue()
        all_classified = set().union(*_ALL_TIER_SETS)

        missing = []
        for tool in catalogue:
            key = tuple(tool["_command_path"])
            membership = sum(key in bucket for bucket in _ALL_TIER_SETS)
            if membership != 1:
                missing.append((key, membership))

        assert not missing, (
            f"commands not classified in exactly one tier: {missing}. "
            f"Classified set has {len(all_classified)} entries for "
            f"{len(catalogue)} catalogue commands."
        )

    def test_no_stale_entries_for_commands_that_no_longer_exist(self):
        """The reverse check: every classified path must still be a real command."""
        catalogue_paths = {tuple(tool["_command_path"]) for tool in build_catalogue()}
        all_classified = set().union(*_ALL_TIER_SETS)

        stale = all_classified - catalogue_paths
        assert not stale, f"classified paths with no matching command: {stale}"


class TestRequiresApproval:
    """Truth table: 4 tiers x tainted/untainted."""

    def test_read_only_untainted_no_approval(self):
        assert requires_approval(["file", "hash"], tainted=False) is False

    def test_read_only_tainted_no_approval(self):
        """Reads stay auto-runnable even on a tainted run - they can't mutate anything."""
        assert requires_approval(["file", "hash"], tainted=True) is False

    def test_case_write_untainted_no_approval(self):
        assert requires_approval(["case", "add"], tainted=False) is False

    def test_case_write_tainted_requires_approval(self):
        """A tainted run may not write even to the case without a human."""
        assert requires_approval(["case", "add"], tainted=True) is True

    def test_taint_gated_untainted_no_approval(self):
        """Auto-run on a clean run: no adversary text has entered the run."""
        assert requires_approval(["network", "dns"], tainted=False) is False

    def test_taint_gated_tainted_requires_approval(self):
        """A tainted run may not pick this tool's DNS-query target without a human."""
        assert requires_approval(["network", "dns"], tainted=True) is True

    def test_external_mutation_untainted_requires_approval(self):
        """External mutations always need a human, tainted or not."""
        assert requires_approval(["malware", "submit"], tainted=False) is True

    def test_external_mutation_tainted_requires_approval(self):
        assert requires_approval(["malware", "submit"], tainted=True) is True


class TestTaintGated:
    """
    `network dns` and `intel whois` route a model-chosen label to whatever
    infrastructure is authoritative for it, rather than to a fixed host -
    the exfiltration channel N2 closed. Fixed-host lookups (the label is a
    query parameter to VT/crt.sh/etc., never routed to attacker-chosen
    infrastructure) must stay auto-runnable even when tainted.
    """

    def test_network_dns_and_intel_whois_are_taint_gated(self):
        assert tier_for(["network", "dns"]) is Tier.TAINT_GATED
        assert tier_for(["intel", "whois"]) is Tier.TAINT_GATED

    @pytest.mark.parametrize(
        "path",
        [
            ["intel", "enrich"],
            ["intel", "geoip"],
            ["intel", "cve"],
            ["network", "ct-subdomains"],
            ["phishing", "reputation"],
        ],
    )
    def test_fixed_host_lookups_stay_read_only_even_when_tainted(self, path):
        assert tier_for(path) is Tier.READ_ONLY
        assert requires_approval(path, tainted=True) is False


class TestReclassifiedCommands:
    """
    Tier assertions for the commands the security review reclassified.
    Group-level whitelisting used to make these READ_ONLY (or, for cf
    list/test, gated only because `ir` wasn't in any allow-group); reading
    the actual implementation changes several of them.
    """

    def test_network_headers_and_ports_are_mutating(self):
        """Direct outbound requests/scans to an attacker-supplied target."""
        assert tier_for(["network", "headers"]) is Tier.EXTERNAL_MUTATION
        assert tier_for(["network", "ports"]) is Tier.EXTERNAL_MUTATION

    def test_ai_analyze_commands_are_mutating(self):
        """Both ship content to a third-party LLM."""
        assert tier_for(["logs", "ai-analyze"]) is Tier.EXTERNAL_MUTATION
        assert tier_for(["phishing", "ai-analyze"]) is Tier.EXTERNAL_MUTATION

    def test_report_generate_is_mutating(self):
        """Ships case contents to a third-party LLM by default."""
        assert tier_for(["report", "generate"]) is Tier.EXTERNAL_MUTATION

    def test_file_baseline_is_mutating(self):
        """Required arbitrary write-target path with no safe default."""
        assert tier_for(["file", "baseline"]) is Tier.EXTERNAL_MUTATION

    def test_cf_list_and_test_are_read_only(self):
        """Genuine Cloudflare reads - no rule is created or changed."""
        assert tier_for(["ir", "cf", "list"]) is Tier.READ_ONLY
        assert tier_for(["ir", "cf", "test"]) is Tier.READ_ONLY

    def test_case_status_is_read_only(self):
        """A tainted agent must still be able to read its own case status."""
        assert tier_for(["case", "status"]) is Tier.READ_ONLY


class TestHazardsFoundInThisReview:
    """
    Beyond the confirmed hazards above, reading every command's
    implementation (rather than trusting its group or its name) turned up
    additional commands with the same shape of hazard. Pinned here so they
    can't quietly slide back to READ_ONLY.
    """

    def test_phishing_analyze_is_mutating(self):
        """
        Not just `ai-analyze`: the general `analyze` command calls the LLM
        too whenever an OpenAI/Anthropic key is available (including via
        the environment, not just an explicit flag) and --quick isn't set.
        """
        assert tier_for(["phishing", "analyze"]) is Tier.EXTERNAL_MUTATION

    def test_phishing_url_expand_is_mutating(self):
        """--expand fetches the attacker-supplied URL directly (SSRF-shaped)."""
        assert tier_for(["phishing", "url"]) is Tier.EXTERNAL_MUTATION

    def test_network_ssl_check_is_mutating(self):
        """Opens a direct socket to an attacker-supplied host:port."""
        assert tier_for(["network", "ssl-check"]) is Tier.EXTERNAL_MUTATION

    def test_osint_domain_is_mutating(self):
        """Embeds the same direct SSL connection as network ssl-check."""
        assert tier_for(["osint", "domain"]) is Tier.EXTERNAL_MUTATION

    def test_ir_collect_is_mutating(self):
        """
        --output-dir is a model-settable write-target directory that the
        bridge does not strip (it only strips options literally named
        `output`, not `output_dir`).
        """
        assert tier_for(["ir", "collect"]) is Tier.EXTERNAL_MUTATION


class TestTierPinning:
    """
    TestCompleteness proves every command is a member of exactly one set;
    it does NOT prove that set maps to the tier its own name claims - e.g.
    moving `report package` from `_CASE_WRITE` into `_READ_ONLY` would
    leave every completeness test green. Pin membership -> tier directly
    for CASE_WRITE and TAINT_GATED. EXTERNAL_MUTATION is already fully
    pinned member-by-member above (TestTiering, TestReclassifiedCommands,
    TestHazardsFoundInThisReview together cover all 16 entries) - keep it
    that way rather than adding a parametrized duplicate here.
    """

    @pytest.mark.parametrize("path", sorted(_CASE_WRITE))
    def test_case_write_members_tier_as_case_write(self, path):
        assert tier_for(list(path)) is Tier.CASE_WRITE

    @pytest.mark.parametrize("path", sorted(_TAINT_GATED))
    def test_taint_gated_members_tier_as_taint_gated(self, path):
        assert tier_for(list(path)) is Tier.TAINT_GATED
