"""Tests for MITRE ATT&CK lookup."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from bsot.intel.mitre import (
    _condense, get_technique, search_techniques, techniques_by_tactic, list_tactics,
)


BUNDLE = {
    "id": "bundle--test",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110",
                 "url": "https://attack.mitre.org/techniques/T1110"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_platforms": ["Windows", "Linux"],
            "x_mitre_detection": "Monitor authentication logs.",
            "x_mitre_data_sources": ["Authentication logs"],
            "x_mitre_is_subtechnique": False,
        },
        {
            "type": "attack-pattern",
            "name": "Password Guessing",
            "description": "Guessing passwords systematically.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110.001",
                 "url": "https://attack.mitre.org/techniques/T1110/001"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_is_subtechnique": True,
        },
        {
            "type": "attack-pattern",
            "name": "Deprecated Thing",
            "description": "Old technique.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_deprecated": True,
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Thing",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T8888"}
            ],
        },
        {
            "type": "intrusion-set",
            "name": "APT29",
            "aliases": ["Cozy Bear"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0016"}
            ],
        },
    ],
}


@pytest.fixture
def data():
    return _condense(BUNDLE)


class TestCondense:
    def test_extracts_techniques(self, data):
        assert "T1110" in data["techniques"]
        assert data["techniques"]["T1110"]["name"] == "Brute Force"

    def test_extracts_tactics_and_platforms(self, data):
        tech = data["techniques"]["T1110"]

        assert tech["tactics"] == ["credential-access"]
        assert "Windows" in tech["platforms"]

    def test_skips_revoked(self, data):
        assert "T8888" not in data["techniques"]

    def test_keeps_but_marks_deprecated(self, data):
        assert data["techniques"]["T9999"]["deprecated"] is True

    def test_extracts_groups(self, data):
        assert data["groups"]["G0016"]["name"] == "APT29"

    def test_marks_subtechniques(self, data):
        assert data["techniques"]["T1110.001"]["is_subtechnique"] is True
        assert data["techniques"]["T1110"]["is_subtechnique"] is False


class TestLookup:
    def test_exact_id(self, data):
        assert get_technique(data, "T1110")["name"] == "Brute Force"

    def test_case_insensitive(self, data):
        assert get_technique(data, "t1110")["name"] == "Brute Force"

    def test_subtechnique_id(self, data):
        assert get_technique(data, "T1110.001")["name"] == "Password Guessing"

    def test_unknown_returns_none(self, data):
        assert get_technique(data, "T0000") is None


class TestSearch:
    def test_exact_name_ranks_first(self, data):
        results = search_techniques(data, "brute force")
        assert results[0]["id"] == "T1110"

    def test_description_match(self, data):
        results = search_techniques(data, "systematically")
        assert any(r["id"] == "T1110.001" for r in results)

    def test_deprecated_excluded(self, data):
        assert not [r for r in search_techniques(data, "old technique") if r["id"] == "T9999"]

    def test_no_match_is_empty(self, data):
        assert search_techniques(data, "zzzznotathing") == []


class TestByTactic:
    def test_lists_tactic_members(self, data):
        ids = {t["id"] for t in techniques_by_tactic(data, "credential-access")}

        assert "T1110" in ids
        assert "T1110.001" in ids

    def test_deprecated_excluded(self, data):
        ids = {t["id"] for t in techniques_by_tactic(data, "credential-access")}
        assert "T9999" not in ids

    def test_counts_exclude_deprecated(self, data):
        assert list_tactics(data)["credential-access"] == 2


class TestMitreCommand:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def _invoke(self, runner, data, *args):
        from bsot.intel.cli import intel
        with patch("bsot.intel.mitre.load_attack_data", return_value=data):
            return runner.invoke(intel, ["mitre", *args])

    def test_lookup_json(self, runner, data):
        result = self._invoke(runner, data, "T1110", "--json")
        assert json.loads(result.output)["name"] == "Brute Force"

    def test_unknown_exits_1(self, runner, data):
        assert self._invoke(runner, data, "T0000").exit_code == 1

    def test_requires_an_argument(self, runner, data):
        assert self._invoke(runner, data).exit_code == 2

    def test_search_json(self, runner, data):
        result = self._invoke(runner, data, "--search", "brute", "--json")
        assert json.loads(result.output)["results"][0]["id"] == "T1110"

    def test_list_tactics_json(self, runner, data):
        result = self._invoke(runner, data, "--list-tactics", "--json")
        assert json.loads(result.output)["credential-access"] == 2
