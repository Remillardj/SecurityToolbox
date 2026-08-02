"""Tests for the phishing url command."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from bsot.phishing.cli import phishing


@pytest.fixture
def runner():
    return CliRunner()


class TestInput:
    def test_accepts_plain_url(self, runner):
        result = runner.invoke(phishing, ["url", "http://example.com/x", "--json"])
        data = json.loads(result.output)

        assert data["results"][0]["host"] == "example.com"

    def test_accepts_defanged_url(self, runner):
        """Analysts paste defanged URLs straight out of tickets."""
        result = runner.invoke(phishing, ["url", "hxxp[://]evil[.]com/login", "--json"])
        data = json.loads(result.output)

        assert data["results"][0]["url"] == "http://evil.com/login"
        assert data["results"][0]["host"] == "evil.com"

    def test_reads_stdin(self, runner):
        result = runner.invoke(
            phishing, ["url", "-", "--json"],
            input="http://a.example.com\nhttp://b.example.com\n",
        )
        data = json.loads(result.output)

        assert data["count"] == 2

    def test_reads_file(self, runner, tmp_path):
        listing = tmp_path / "urls.txt"
        listing.write_text("http://a.example.com\nhttp://b.example.com\n")

        result = runner.invoke(phishing, ["url", "-f", str(listing), "--json"])
        assert json.loads(result.output)["count"] == 2

    def test_rejects_garbage(self, runner):
        result = runner.invoke(phishing, ["url", "not a url at all"])
        assert result.exit_code == 2

    def test_no_input_exits_2(self, runner):
        result = runner.invoke(phishing, ["url", "--json"], input="")
        assert result.exit_code == 2


class TestParsing:
    def test_extracts_components(self, runner):
        result = runner.invoke(
            phishing, ["url", "https://host.example.com:8443/a/b?c=d", "--json"]
        )
        entry = json.loads(result.output)["results"][0]

        assert entry["host"] == "host.example.com"
        assert entry["port"] == 8443
        assert entry["path"] == "/a/b"
        assert entry["scheme"] == "https"

    def test_bare_host_gets_scheme(self, runner):
        result = runner.invoke(phishing, ["url", "example.com", "--json"])
        assert json.loads(result.output)["results"][0]["host"] == "example.com"


class _Redirected:
    """Stand-in for a requests response that followed redirects."""
    url = "https://final.example.com/landing"
    status_code = 200

    class _Hop:
        def __init__(self, url):
            self.url = url

    history = [_Hop("http://short.example.com/abc")]


class TestExpand:
    def test_records_redirect_chain(self, runner):
        with patch("requests.get", return_value=_Redirected()):
            result = runner.invoke(
                phishing, ["url", "http://short.example.com/abc", "--expand", "--json"]
            )
        entry = json.loads(result.output)["results"][0]

        assert entry["final_url"] == "https://final.example.com/landing"
        assert entry["redirects"] == ["http://short.example.com/abc"]

    def test_expansion_failure_is_reported_not_fatal(self, runner):
        import requests

        with patch("requests.get", side_effect=requests.exceptions.ConnectTimeout("nope")):
            result = runner.invoke(
                phishing, ["url", "http://unreachable.example.com", "--expand", "--json"]
            )
        entry = json.loads(result.output)["results"][0]

        assert "expand_error" in entry
        assert result.exit_code == 0


class TestOutput:
    def test_json_keeps_urls_refanged(self, runner):
        """Machine consumers need real values; only human output is defanged."""
        result = runner.invoke(phishing, ["url", "http://evil.com", "--json"])

        assert json.loads(result.output)["results"][0]["url"] == "http://evil.com"

    def test_human_output_is_defanged(self, runner):
        result = runner.invoke(phishing, ["url", "http://evil.com"])

        assert "http://evil.com" not in result.output
        assert "evil[.]com" in result.output
