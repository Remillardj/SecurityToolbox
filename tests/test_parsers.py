"""Tests for log parsers."""


from bsot.logs.parsers import parse_log, detect_format


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


class TestCEF:
    HEADER = (
        "CEF:0|Security Vendor|Threat Manager|1.5.2|100|worm detected|8|"
    )

    def test_header_fields(self, tmp_path):
        path = write(tmp_path, "t.cef", self.HEADER + "src=10.0.0.1 dst=10.0.0.2 suser=alice\n")
        events = parse_log(path, format="cef")

        assert len(events) == 1
        e = events[0]
        assert e.extra["vendor"] == "Security Vendor"
        assert e.extra["product"] == "Threat Manager"
        assert e.extra["signature_id"] == "100"
        assert e.severity == "8"
        assert e.message == "worm detected"

    def test_cef_version_and_device_version_both_kept(self, tmp_path):
        """CEF version (0) and device version (1.5.2) are distinct fields."""
        path = write(tmp_path, "t.cef", self.HEADER + "src=10.0.0.1\n")
        extra = parse_log(path, format="cef")[0].extra

        assert extra["version"] == "0"
        assert extra["device_version"] == "1.5.2"

    def test_extension_fields_mapped(self, tmp_path):
        path = write(tmp_path, "t.cef", self.HEADER + "src=10.0.0.1 dst=10.0.0.2 suser=alice\n")
        e = parse_log(path, format="cef")[0]

        assert e.source_ip == "10.0.0.1"
        assert e.destination_ip == "10.0.0.2"
        assert e.user == "alice"

    def test_no_extension_field(self, tmp_path):
        """A CEF line with no extension is still valid (7 pipe-delimited parts)."""
        path = write(tmp_path, "t.cef", "CEF:0|Vendor|Product|1.0|100|test event|5|\n")
        events = parse_log(path, format="cef")

        assert len(events) == 1
        assert events[0].message == "test event"

    def test_extension_value_with_spaces(self, tmp_path):
        """CEF extension values may contain spaces; the next key= ends the value."""
        line = self.HEADER + "src=10.0.0.1 msg=this is a long message dst=10.0.0.2\n"
        path = write(tmp_path, "t.cef", line)
        e = parse_log(path, format="cef")[0]

        assert e.extra["msg"] == "this is a long message"
        assert e.destination_ip == "10.0.0.2"

    def test_escaped_pipe_in_header(self, tmp_path):
        r"""A \| inside a header field is escaped data, not a delimiter."""
        line = r"CEF:0|Vendor|Pro\|duct|1.0|100|test event|5|src=10.0.0.1" + "\n"
        path = write(tmp_path, "t.cef", line)
        e = parse_log(path, format="cef")[0]

        assert e.extra["product"] == "Pro|duct"
        assert e.message == "test event"


class TestSyslog:
    def test_basic(self, tmp_path):
        line = "Jan 15 10:30:45 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 22\n"
        path = write(tmp_path, "auth.log", line)
        events = parse_log(path, format="syslog")

        assert len(events) == 1
        assert events[0].host == "myhost"
        assert events[0].source_ip == "1.2.3.4"


class TestJSON:
    def test_jsonl(self, tmp_path):
        content = (
            '{"timestamp": "2026-01-15T10:30:45", "message": "test", "src_ip": "1.2.3.4"}\n'
            '{"timestamp": "2026-01-15T10:30:46", "message": "test2"}\n'
        )
        path = write(tmp_path, "log.jsonl", content)
        events = parse_log(path, format="json")

        assert len(events) == 2
        assert events[0].source_ip == "1.2.3.4"

    def test_malformed_line_skipped(self, tmp_path):
        content = '{"message": "good"}\nnot json at all\n{"message": "also good"}\n'
        path = write(tmp_path, "log.jsonl", content)

        assert len(parse_log(path, format="json")) == 2


class TestCLF:
    def test_common_log_format(self, tmp_path):
        line = '192.168.1.1 - - [15/Jan/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234\n'
        path = write(tmp_path, "access.log", line)
        events = parse_log(path, format="clf")

        assert len(events) == 1
        assert events[0].source_ip == "192.168.1.1"


class TestDetectFormat:
    def test_detects_json_by_extension(self, tmp_path):
        assert detect_format(write(tmp_path, "x.json", "{}")) == "json"

    def test_detects_cef_by_content(self, tmp_path):
        path = write(tmp_path, "x.log", "CEF:0|V|P|1.0|1|evt|5|src=1.2.3.4\n")
        assert detect_format(path) == "cef"


class TestLimit:
    def test_limit_respected(self, tmp_path):
        content = "".join(f'{{"message": "m{i}"}}\n' for i in range(10))
        path = write(tmp_path, "log.jsonl", content)

        assert len(parse_log(path, format="json", limit=3)) == 3
