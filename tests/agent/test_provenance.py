"""Tests for finding attribution."""

import pytest

from bsot.agent.provenance import Finding, FindingLog, UnsourcedFinding


class TestFinding:
    def test_requires_a_source_command(self):
        with pytest.raises(UnsourcedFinding):
            Finding(claim="the host is compromised", source_command="", exit_code=0)

    def test_accepts_a_sourced_claim(self):
        finding = Finding(
            claim="binary is unsigned",
            source_command="bsot malware pe sample.exe --json",
            exit_code=0,
            evidence="authentihash_present: false",
        )

        assert finding.claim == "binary is unsigned"

    def test_confidence_defaults_to_medium(self):
        finding = Finding(claim="x", source_command="bsot file hash a", exit_code=0)

        assert finding.confidence == "medium"

    def test_rejects_unknown_confidence(self):
        with pytest.raises(ValueError):
            Finding(
                claim="x", source_command="bsot file hash a",
                exit_code=0, confidence="certain",
            )


class TestFindingLog:
    def test_records_and_lists(self):
        log = FindingLog()
        log.add(Finding(claim="a", source_command="bsot file hash x", exit_code=0))

        assert len(log.findings) == 1

    def test_serialises_for_the_case(self):
        log = FindingLog()
        log.add(Finding(
            claim="unsigned binary",
            source_command="bsot malware pe s.exe --json",
            exit_code=0,
            evidence="authentihash_present: false",
        ))
        payload = log.to_dict()

        assert payload["count"] == 1
        entry = payload["findings"][0]
        assert entry["source_command"] == "bsot malware pe s.exe --json"
        assert entry["evidence"] == "authentihash_present: false"

    def test_every_finding_resolves_to_a_command(self):
        """The audit property the whole design rests on."""
        log = FindingLog()
        log.add(Finding(claim="a", source_command="bsot file hash x", exit_code=0))
        log.add(Finding(claim="b", source_command="bsot intel enrich 1.1.1.1", exit_code=1))

        assert all(f.source_command for f in log.findings)
