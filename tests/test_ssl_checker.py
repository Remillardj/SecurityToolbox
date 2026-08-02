"""Regression tests for the SSL checker."""

from bsot.network.ssl_checker import SSLChecker, SSLResult


class TestSerialNumber:
    """getpeercert() returns serialNumber as a hex string, not an int.

    Passing it to hex() raised TypeError, which the broad except in check()
    swallowed into result.error - so every real certificate check failed.
    """

    def _parse(self, serial):
        checker = SSLChecker()
        result = SSLResult(host="example.com", port=443)
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "serialNumber": serial,
            "version": 3,
            "subjectAltName": (("DNS", "example.com"),),
        }
        checker._parse_certificate(cert, result)
        return result

    def test_hex_string_serial_does_not_raise(self):
        result = self._parse("72010E03F4A067FE4E796266430718F6")

        assert result.serial_number == "72010E03F4A067FE4E796266430718F6"

    def test_lowercase_serial_normalised(self):
        assert self._parse("abcdef123456").serial_number == "ABCDEF123456"

    def test_integer_serial_still_supported(self):
        assert self._parse(255).serial_number == "FF"

    def test_missing_serial_is_safe(self):
        checker = SSLChecker()
        result = SSLResult(host="example.com", port=443)
        checker._parse_certificate({"subject": (), "issuer": ()}, result)

        assert result.serial_number == ""

    def test_certificate_fields_still_parsed(self):
        result = self._parse("0A0B")

        assert result.cert_subject["common_name"] == "example.com"
        assert result.cert_issuer["common_name"] == "Test CA"
        assert "example.com" in result.san
