"""Tests for safe (defanged) display of indicators."""

import pytest

from bsot.utils import safe, set_defang, defang_enabled


@pytest.fixture(autouse=True)
def _default_on():
    set_defang(True)
    yield
    set_defang(True)


class TestSafe:
    def test_defangs_http_scheme(self):
        assert safe("http://evil.com") == "hxxp[://]evil[.]com"

    def test_defangs_https_scheme(self):
        assert safe("https://evil.com") == "hxxps[://]evil[.]com"

    def test_defangs_ipv4(self):
        assert safe("beacon to 203.0.113.42") == "beacon to 203[.]0[.]113[.]42"

    def test_defangs_domain_without_scheme(self):
        assert safe("evil-domain.xyz") == "evil-domain[.]xyz"

    def test_defangs_subdomain(self):
        assert safe("a.b.evil.com") == "a[.]b[.]evil[.]com"

    def test_defangs_email_domain(self):
        assert safe("attacker@evil.com") == "attacker@evil[.]com"

    def test_leaves_localhost_alone(self):
        assert safe("connect to localhost:8080") == "connect to localhost:8080"

    def test_leaves_loopback_alone(self):
        assert safe("bound on 127.0.0.1") == "bound on 127.0.0.1"

    def test_leaves_prose_alone(self):
        text = "An ordinary sentence with no indicators in it."
        assert safe(text) == text

    def test_empty_string(self):
        assert safe("") == ""

    def test_result_is_not_clickable(self):
        """The whole point: no live scheme survives."""
        out = safe("http://evil.com/x and https://bad.net/y")

        assert "http://" not in out
        assert "https://" not in out


class TestOptOut:
    def test_disabled_passes_through(self):
        set_defang(False)

        assert safe("http://evil.com") == "http://evil.com"
        assert defang_enabled() is False

    def test_re_enabling_restores(self):
        set_defang(False)
        set_defang(True)

        assert safe("http://evil.com") == "hxxp[://]evil[.]com"


class TestRoundTrip:
    def test_refang_recovers_the_original(self):
        from bsot.utils import refang_url

        original = "http://evil.com/payload"
        assert refang_url(safe(original)) == original


class TestRefangVariants:
    """refang must handle the separator forms analysts paste in."""

    @pytest.mark.parametrize("defanged,expected", [
        ("hxxp[://]evil[.]com", "http://evil.com"),
        ("hxxps[://]evil[.]com", "https://evil.com"),
        ("hxxp[:]//evil[.]com", "http://evil.com"),
        ("hxxp://evil[.]com", "http://evil.com"),
        ("hxxps://evil(.)com", "https://evil.com"),
        ("hxxp[://]evil[dot]com", "http://evil.com"),
    ])
    def test_variants(self, defanged, expected):
        from bsot.utils import refang_url

        assert refang_url(defanged) == expected

    def test_plain_url_is_untouched(self):
        from bsot.utils import refang_url

        assert refang_url("http://example.com") == "http://example.com"


class TestIOCUtilsRefang:
    """The intel refang command's implementation.

    It replaced `hxxp://` before normalising `[://]`, so `hxxp[://]evil[.]com`
    came back as `hxxp://evil.com` with the scheme still defanged.
    """

    @pytest.mark.parametrize("defanged,expected", [
        ("hxxp[://]evil[.]com", "http://evil.com"),
        ("hxxps[://]bad[.]net/path", "https://bad.net/path"),
        ("hxxp://legacy[.]com", "http://legacy.com"),
        ("hXXps://caps[.]com", "https://caps.com"),
        ("1[.]2[.]3[.]4", "1.2.3.4"),
        ("user[@]evil[.]com", "user@evil.com"),
        ("evil(dot)com", "evil.com"),
    ])
    def test_refang_forms(self, defanged, expected):
        from bsot.intel.ioc_utils import refang

        assert refang(defanged) == expected

    @pytest.mark.parametrize("original", [
        "http://evil.com/payload",
        "https://bad.net/a/b?c=d",
        "203.0.113.42",
        "evil-domain.xyz",
    ])
    def test_round_trip_through_safe(self, original):
        """safe() then refang() must return exactly what went in."""
        from bsot.intel.ioc_utils import refang

        assert refang(safe(original)) == original
