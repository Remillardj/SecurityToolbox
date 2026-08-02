"""Tests for finding attribution."""

import dataclasses

import pytest

from bsot.agent.provenance import (
    Finding,
    FindingLog,
    UnsourcedFinding,
    build_record_finding_tool,
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

    @pytest.mark.parametrize("bad", [None, "0", "failed", {"code": 0}, True, False])
    def test_rejects_non_int_exit_code(self, bad):
        """
        Judgment call: bool is rejected even though it's an int subclass.
        A JSON `true`/`false` exit_code is a plausible malformed tool call,
        and a boolean is not a process return code even though Python's
        isinstance(True, int) says otherwise.
        """
        with pytest.raises(TypeError):
            Finding(claim="x", source_command="bsot file hash a", exit_code=bad)

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
        tool = build_record_finding_tool()

        assert tool["name"] == "record_finding"
        assert isinstance(tool["description"], str)
        assert tool["description"]

        schema = tool["input_schema"]
        assert schema["type"] == "object"
        assert set(schema["required"]) == {"claim", "source_command", "exit_code"}

        properties = schema["properties"]
        assert set(properties) == {
            "claim", "source_command", "exit_code", "evidence", "confidence",
        }
        assert properties["confidence"]["enum"] == ["low", "medium", "high"]

    def test_returns_a_fresh_dict_each_call(self):
        """
        A shared module-level dict would let one caller's in-place edit
        (e.g. Task 11 stripping keys before the catalogue reaches the model)
        leak into every other caller - including through nested dicts and
        lists, which a shallow freeze would not catch. Mutate everything
        mutable in one copy and confirm a second call is untouched.
        """
        first = build_record_finding_tool()
        first["name"] = "clobbered"
        first["input_schema"]["properties"]["claim"]["type"] = "clobbered"
        first["input_schema"]["required"].append("clobbered")
        first["input_schema"]["properties"]["confidence"]["enum"].append("clobbered")

        second = build_record_finding_tool()

        assert second["name"] == "record_finding"
        assert second["input_schema"]["properties"]["claim"]["type"] == "string"
        assert "clobbered" not in second["input_schema"]["required"]
        assert "clobbered" not in second["input_schema"]["properties"]["confidence"]["enum"]

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

    def test_wrong_typed_field_returns_error_not_raised(self):
        """
        Pins that record_finding catches TypeError, not just ValueError -
        a null field (the most common malformed model output) drives a
        TypeError through Finding's claim guard.
        """
        log = FindingLog()
        result = record_finding(log, {
            "claim": None, "source_command": "bsot file hash a", "exit_code": 0,
        })

        assert result["recorded"] is False
        assert "error" in result
        assert len(log.findings) == 0

    def test_non_dict_params_returns_error_not_raised(self):
        """
        Non-dict params (e.g. the model sending null instead of an object)
        currently fail only as a side effect of subscripting raising
        TypeError - pinned explicitly so that stays true.
        """
        assert record_finding(FindingLog(), None)["recorded"] is False
