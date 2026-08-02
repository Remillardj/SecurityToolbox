"""Tests for newly added commands."""

import base64
import gzip
import json
import urllib.parse
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from bsot.data.encoders import magic_decode
from bsot.data.cli import data
from bsot.network.cli import network


@pytest.fixture
def runner():
    return CliRunner()


class TestMagicDecode:
    def test_single_layer_base64(self):
        payload = base64.b64encode(b"hello world").decode()
        steps = magic_decode(payload)

        assert [s["encoding"] for s in steps] == ["base64"]
        assert steps[-1]["output"] == "hello world"

    def test_nested_base64(self):
        inner = base64.b64encode(b"the secret").decode()
        outer = base64.b64encode(inner.encode()).decode()

        steps = magic_decode(outer)
        assert [s["encoding"] for s in steps] == ["base64", "base64"]
        assert steps[-1]["output"] == "the secret"

    def test_url_encoding(self):
        steps = magic_decode(urllib.parse.quote("hello world & more"))

        assert steps[-1]["output"] == "hello world & more"

    def test_plaintext_yields_no_steps(self):
        assert magic_decode("just some ordinary english words") == []

    def test_respects_max_depth(self):
        payload = b"deeply nested payload"
        for _ in range(6):
            payload = base64.b64encode(payload)

        steps = magic_decode(payload.decode(), max_depth=3)
        assert len(steps) <= 3

    def test_does_not_loop_forever(self):
        """rot13 is its own inverse; a naive walker would ping-pong."""
        steps = magic_decode("uryyb jbeyq", max_depth=10)
        assert len(steps) < 10

    def test_binary_garbage_is_rejected(self):
        """A hex-looking string that decodes to binary should not be taken."""
        steps = magic_decode("deadbeefcafebabe0011223344556677")
        for step in steps:
            assert step["printable_ratio"] >= 0.90


class TestMagicCommand:
    def test_decodes_and_reports_chain(self, runner):
        inner = base64.b64encode(b"payload here").decode()
        outer = base64.b64encode(inner.encode()).decode()

        result = runner.invoke(data, ["magic", outer, "--json"])
        parsed = json.loads(result.output)

        assert parsed["decoded"] == "payload here"
        assert parsed["layers"] == ["base64", "base64"]

    def test_reads_stdin(self, runner):
        payload = base64.b64encode(b"from stdin").decode()
        result = runner.invoke(data, ["magic", "-", "--json"], input=payload)

        assert json.loads(result.output)["decoded"] == "from stdin"

    def test_exit_code_when_nothing_decodes(self, runner):
        result = runner.invoke(data, ["magic", "plain english text here"])

        assert result.exit_code == 1


CRTSH_RESPONSE = [
    {
        "name_value": "www.example.com\nexample.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2027-01-01T00:00:00",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    },
    {
        "name_value": "*.api.example.com",
        "not_before": "2026-02-01T00:00:00",
        "not_after": "2027-02-01T00:00:00",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    },
    {
        "name_value": "old.example.com",
        "not_before": "2020-01-01T00:00:00",
        "not_after": "2021-01-01T00:00:00",
        "issuer_name": "C=US, O=DigiCert",
    },
    {
        "name_value": "notmine.other.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2027-01-01T00:00:00",
        "issuer_name": "C=US, O=Other",
    },
]


class _FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class TestCTSubdomains:
    def _run(self, runner, *args):
        with patch("requests.get", return_value=_FakeResponse(CRTSH_RESPONSE)):
            result = runner.invoke(network, ["ct-subdomains", "example.com", "--json", *args])
        return json.loads(result.output)

    def test_extracts_and_dedupes(self, runner):
        names = {s["name"] for s in self._run(runner)["subdomains"]}

        assert "www.example.com" in names
        assert "example.com" in names

    def test_strips_wildcard_prefix(self, runner):
        names = {s["name"] for s in self._run(runner)["subdomains"]}

        assert "api.example.com" in names
        assert "*.api.example.com" not in names

    def test_excludes_other_domains(self, runner):
        names = {s["name"] for s in self._run(runner)["subdomains"]}

        assert not any("other.com" in n for n in names)

    def test_expired_excluded_by_default(self, runner):
        names = {s["name"] for s in self._run(runner)["subdomains"]}
        assert "old.example.com" not in names

        with_expired = {s["name"] for s in self._run(runner, "--include-expired")["subdomains"]}
        assert "old.example.com" in with_expired

    def test_rejects_invalid_domain(self, runner):
        result = runner.invoke(network, ["ct-subdomains", "not a domain"])
        assert result.exit_code == 2

    def test_retries_then_fails_cleanly_on_503(self, runner):
        class Down:
            status_code = 503

            def raise_for_status(self):
                pass

            def json(self):
                return []

        with patch("requests.get", return_value=Down()), patch("time.sleep"):
            result = runner.invoke(network, ["ct-subdomains", "example.com"])

        assert result.exit_code == 2
        assert "unavailable" in result.output.lower()


class TestMagicCompression:
    def test_base64_wrapping_gzip(self):
        payload = base64.b64encode(gzip.compress(b"compressed payload")).decode()
        steps = magic_decode(payload)

        assert [s["encoding"] for s in steps] == ["base64", "gzip"]
        assert steps[-1]["output"] == "compressed payload"

    def test_base64_wrapping_zlib(self):
        import zlib

        payload = base64.b64encode(zlib.compress(b"zlib payload")).decode()
        steps = magic_decode(payload)

        assert [s["encoding"] for s in steps] == ["base64", "zlib"]
        assert steps[-1]["output"] == "zlib payload"

    def test_url_then_base64(self):
        inner = base64.b64encode(b"nested through url").decode()
        payload = urllib.parse.quote(inner)
        steps = magic_decode(payload)

        assert steps[-1]["output"] == "nested through url"
