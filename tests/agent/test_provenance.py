"""Tests for finding attribution."""

import dataclasses

import pytest

from bsot.agent.provenance import (
    RECORD_FINDING_TOOL,
    Finding,
    FindingLog,
    UnsourcedFinding,
    record_finding,
)


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

    def test_confidence_is_case_sensitive(self):
        """Judgment call: strict, not normalized - see provenance.py."""
        with pytest.raises(ValueError):
            Finding(
                claim="x", source_command="bsot file hash a",
                exit_code=0, confidence="High",
            )

    def test_rejects_whitespace_only_source_command(self):
        with pytest.raises(UnsourcedFinding):
            Finding(claim="x", source_command="   ", exit_code=0)

    @pytest.mark.parametrize("bad", [None, 0, [], True])
    def test_rejects_non_str_source_command(self, bad):
        with pytest.raises(TypeError):
            Finding(claim="x", source_command=bad, exit_code=0)

    def test_rejects_blank_claim(self):
        with pytest.raises(ValueError):
            Finding(claim="", source_command="bsot file hash a", exit_code=0)

    def test_rejects_whitespace_only_claim(self):
        with pytest.raises(ValueError):
            Finding(claim="   ", source_command="bsot file hash a", exit_code=0)

    @pytest.mark.parametrize("bad", [None, 0, [], True])
    def test_rejects_non_str_claim(self, bad):
        with pytest.raises(TypeError):
            Finding(claim=bad, source_command="bsot file hash a", exit_code=0)

    @pytest.mark.parametrize("bad", [None, 0, [], b"\xff\xfeMZ"])
    def test_rejects_non_str_evidence(self, bad):
        with pytest.raises(TypeError):
            Finding(
                claim="x", source_command="bsot file hash a",
                exit_code=0, evidence=bad,
            )

    def test_is_frozen(self):
        finding = Finding(claim="x", source_command="bsot file hash a", exit_code=0)

        with pytest.raises(dataclasses.FrozenInstanceError):
            finding.source_command = ""

    def test_to_dict_full_equality(self):
        finding = Finding(
            claim="unsigned binary",
            source_command="bsot malware pe s.exe --json",
            exit_code=0,
            evidence="authentihash_present: false",
            confidence="high",
        )

        assert finding.to_dict() == {
            "claim": "unsigned binary",
            "source_command": "bsot malware pe s.exe --json",
            "exit_code": 0,
            "evidence": "authentihash_present: false",
            "confidence": "high",
        }


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
        assert len(log.findings) == 2
        assert log.to_dict()["count"] == 2

    def test_add_keeps_duplicate_findings(self):
        """Repeat findings from a repeated command are legitimate - no dedup."""
        log = FindingLog()
        log.add(Finding(claim="a", source_command="bsot file hash x", exit_code=0))
        log.add(Finding(claim="a", source_command="bsot file hash x", exit_code=0))

        assert len(log.findings) == 2
        assert log.to_dict()["count"] == 2

    def test_add_rejects_non_finding(self):
        log = FindingLog()

        with pytest.raises(TypeError):
            log.add({"claim": "a", "source_command": "bsot file hash x", "exit_code": 0})

    def test_len_and_iter(self):
        log = FindingLog()
        log.add(Finding(claim="a", source_command="bsot file hash x", exit_code=0))
        log.add(Finding(claim="b", source_command="bsot intel enrich 1.1.1.1", exit_code=1))

        assert len(log) == 2
        assert [f.claim for f in log] == ["a", "b"]

    def test_counts_by_confidence(self):
        log = FindingLog()
        log.add(Finding(
            claim="a", source_command="bsot file hash x", exit_code=0, confidence="high",
        ))
        log.add(Finding(
            claim="b", source_command="bsot file hash y", exit_code=0, confidence="high",
        ))
        log.add(Finding(
            claim="c", source_command="bsot file hash z", exit_code=0, confidence="medium",
        ))

        assert log.counts_by_confidence() == {"high": 2, "medium": 1}
        assert log.to_dict()["counts_by_confidence"] == {"high": 2, "medium": 1}
        # Existing keys stay - Task 7 and Task 12 depend on them.
        assert log.to_dict()["count"] == 3
        assert len(log.to_dict()["findings"]) == 3


class TestRecordFindingTool:
    def test_schema_has_required_keys_and_enum(self):
        assert RECORD_FINDING_TOOL["name"] == "record_finding"
        assert isinstance(RECORD_FINDING_TOOL["description"], str)
        assert RECORD_FINDING_TOOL["description"]

        schema = RECORD_FINDING_TOOL["input_schema"]
        assert schema["type"] == "object"
        assert set(schema["required"]) == {"claim", "source_command", "exit_code"}

        properties = schema["properties"]
        assert set(properties) == {
            "claim", "source_command", "exit_code", "evidence", "confidence",
        }
        assert properties["confidence"]["enum"] == ["low", "medium", "high"]

    def test_valid_call_records_and_returns_count(self):
        log = FindingLog()
        result = record_finding(log, {
            "claim": "binary is unsigned",
            "source_command": "bsot malware pe sample.exe --json",
            "exit_code": 0,
            "evidence": "authentihash_present: false",
            "confidence": "high",
        })

        assert result == {"recorded": True, "count": 1}
        assert len(log.findings) == 1
        assert log.findings[0].confidence == "high"

    def test_unsourced_claim_returns_error_not_raised(self):
        log = FindingLog()
        result = record_finding(log, {
            "claim": "the host is compromised",
            "source_command": "",
            "exit_code": 0,
        })

        assert result["recorded"] is False
        assert "error" in result
        assert len(log.findings) == 0

    def test_unknown_confidence_returns_error_not_raised(self):
        log = FindingLog()
        result = record_finding(log, {
            "claim": "x",
            "source_command": "bsot file hash a",
            "exit_code": 0,
            "confidence": "certain",
        })

        assert result["recorded"] is False
        assert "error" in result
        assert len(log.findings) == 0

    def test_missing_required_key_returns_error_not_raised(self):
        log = FindingLog()
        result = record_finding(log, {
            "claim": "x",
            "exit_code": 0,
            # source_command missing entirely
        })

        assert result["recorded"] is False
        assert "error" in result
        assert len(log.findings) == 0
