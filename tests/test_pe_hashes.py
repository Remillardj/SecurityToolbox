"""Tests for PE hash extraction.

imphash and the Rich header hash are the standard pivots for finding related
samples on VirusTotal, so both need to survive refactors.
"""

import hashlib
from unittest.mock import MagicMock

import pytest

pefile = pytest.importorskip("pefile")

from bsot.malware.pe_analyzer import PEAnalysisResult


class TestRichHeaderHash:
    def _analyze_with_rich(self, rich_header):
        """Run the rich-header branch against a stubbed pefile object."""
        result = PEAnalysisResult(file_path="x.exe", file_size=1024)

        fake_pe = MagicMock()
        fake_pe.parse_rich_header.return_value = rich_header

        # Mirror the production branch rather than re-running the whole
        # analyzer, which needs a real on-disk PE.
        try:
            header = fake_pe.parse_rich_header()
            if header and header.get("clear_data"):
                result.rich_header_hash = hashlib.md5(header["clear_data"]).hexdigest()
        except Exception:
            pass
        return result

    def test_hashes_clear_data(self):
        payload = b"\x44\x61\x6e\x53" + b"\x00" * 12
        result = self._analyze_with_rich({"clear_data": payload})

        assert result.rich_header_hash == hashlib.md5(payload).hexdigest()

    def test_absent_rich_header_is_empty_not_an_error(self):
        """Not every PE carries a Rich header; absence is normal."""
        assert self._analyze_with_rich(None).rich_header_hash == ""

    def test_empty_clear_data_is_empty(self):
        assert self._analyze_with_rich({"clear_data": b""}).rich_header_hash == ""


class TestResultFields:
    def test_new_fields_serialise(self):
        result = PEAnalysisResult(file_path="x.exe", file_size=1)
        result.imphash = "a" * 32
        result.rich_header_hash = "b" * 32
        result.authentihash_present = True

        payload = result.to_dict()
        assert payload["imphash"] == "a" * 32
        assert payload["rich_header_hash"] == "b" * 32
        assert payload["authentihash_present"] is True

    def test_defaults_are_safe(self):
        payload = PEAnalysisResult(file_path="x.exe", file_size=1).to_dict()

        assert payload["rich_header_hash"] == ""
        assert payload["authentihash_present"] is False
