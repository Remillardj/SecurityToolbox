"""
Tests for the bsot subprocess executor.

These are contract tests against the real `bsot` binary - no mocks - because
the whole point of this module is that the JSON contract and the argv shape
are the tested interface. Every case here was verified against the actual
command's behavior first (see the executor-implementation report); where the
plan's assumptions about a command's exit code turned out wrong, the test
asserts what the command actually does.
"""

import os

from bsot.agent.executor import CommandResult, run_command


class TestRunCommand:
    def test_runs_a_read_only_command(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert result.exit_code == 0
        assert result.parsed is not None

    def test_parses_json_output(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert isinstance(result.parsed, list)
        assert "hashes" in result.parsed[0]

    def test_flags_are_passed_when_true_only(self):
        result = run_command(["data", "magic"], {"value": "SGVsbG8gV29ybGQ="})

        assert "--steps" not in result.command
        assert result.exit_code == 0

    def test_records_the_rendered_command(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert result.command.startswith("bsot file hash")
        assert "--json" in result.command

    def test_missing_command_is_reported(self):
        result = run_command(["file", "no-such-command"], {})

        assert result.exit_code != 0
        assert result.error

    # -- Positional arguments: the case the plan's key-name guessing broke.
    # `intel defang` takes IOC as a bare positional; the plan's _render_args
    # would have turned it into a nonexistent `--ioc` flag.

    def test_positional_argument_command_works(self):
        result = run_command(["intel", "defang"], {"ioc": "1.2.3.4"})

        assert result.exit_code == 0
        assert "--ioc" not in result.command
        assert "1[.]2[.]3[.]4" in result.stdout

    def test_command_without_json_support_gets_no_json_flag(self):
        """intel defang has no --json option; appending one exits 2, not 0."""
        result = run_command(["intel", "defang"], {"ioc": "8.8.8.8"})

        assert "--json" not in result.command
        assert result.exit_code == 0

    # -- Renamed options: the Click param name and the real flag can differ.
    # `data magic`'s Click param is `input_file`, backed by `--file`.

    def test_renamed_option_round_trips(self, tmp_path):
        encoded = tmp_path / "encoded.txt"
        encoded.write_text("SGVsbG8gV29ybGQ=")

        result = run_command(["data", "magic"], {"input_file": str(encoded)})

        assert "--file" in result.command
        assert "--input-file" not in result.command
        assert result.exit_code == 0
        assert result.parsed["decoded"] == "Hello World"

    # -- Multiple positionals keep declaration order.
    # `data encode` is `@click.argument('encoding')` then
    # `@click.argument('value', ...)` (bsot/data/cli.py); the rendered
    # command must put ENCODING before VALUE regardless of dict order.

    def test_multiple_positionals_keep_declaration_order(self):
        result = run_command(
            ["data", "encode"],
            # Deliberately supplied out of declaration order.
            {"value": "Hello World", "encoding": "base64"},
        )

        assert result.exit_code == 0
        assert result.stdout.strip() == "SGVsbG8gV29ybGQ="
        idx_encoding = result.command.index("base64")
        idx_value = result.command.index("Hello World")
        assert idx_encoding < idx_value

    # -- Negative toggle: a False flag with a --no-x counterpart must emit
    # the secondary flag, not just be omitted.

    def test_negative_toggle_emits_secondary_opt(self, tmp_path):
        target_dir = tmp_path / "scan"
        target_dir.mkdir()
        bad_file = target_dir / "bad.txt"
        bad_file.write_text("x")
        os.chmod(bad_file, 0o666)  # world-writable: a real finding

        result = run_command(
            ["file", "permissions"],
            {"directory": str(target_dir), "recursive": False},
        )

        assert "--no-recursive" in result.command
        assert "--recursive" not in result.command
        assert result.exit_code == 1
        assert result.parsed["risky_count"] == 1

    # -- shlex quoting: a path with a space must render quoted, not naively
    # space-joined (a naive join would produce a misleading, non-copy-pasteable
    # provenance string).

    def test_command_with_space_in_path_is_shlex_quoted(self, tmp_path):
        spacey_dir = tmp_path / "dir with space"
        spacey_dir.mkdir()
        encoded = spacey_dir / "enc file.txt"
        encoded.write_text("SGVsbG8gV29ybGQ=")

        result = run_command(["data", "magic"], {"input_file": str(encoded)})

        assert result.exit_code == 0
        # shlex.quote wraps a value containing spaces in single quotes; a
        # naive " ".join would leave it bare and unparseable if copy-pasted.
        assert f"'{encoded}'" in result.command

    # -- Unknown params must never be silently turned into a flag.

    def test_unknown_param_is_surfaced_not_guessed_into_a_flag(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(
            ["file", "hash"],
            {"files": [str(target)], "totally_unknown_param": "x"},
        )

        assert "--totally-unknown-param" not in result.command
        assert "totally_unknown_param" in result.error
        # The known, valid params still run the command normally.
        assert result.exit_code == 0

    # -- Exit code 1 (findings) is returned, never raised. Verified against a
    # command that genuinely exits 1 with --json still attached: `data magic`
    # on non-decodable input does NOT exit 1 once --json is passed (verified
    # separately - see report), so this uses `file permissions` finding a
    # real world-writable file instead.

    def test_nonzero_exit_is_returned_not_raised(self, tmp_path):
        target_dir = tmp_path / "scan2"
        target_dir.mkdir()
        bad_file = target_dir / "bad.txt"
        bad_file.write_text("x")
        os.chmod(bad_file, 0o666)

        result = run_command(["file", "permissions"], {"directory": str(target_dir)})

        assert result.exit_code == 1
        assert isinstance(result, CommandResult)

    def test_data_magic_with_json_does_not_exit_1_on_no_match(self):
        """
        Deviation from the plan: the plan used `data magic` on plain text as
        its exit-1 example. With --json attached (which the executor always
        does when supports_json is true), `bsot/data/cli.py`'s magic command
        takes the `if json_output:` branch unconditionally and returns 0,
        emitting `{"decoded": null, ...}` rather than exiting 1. Documented
        here as a regression guard rather than relied on for the exit-1 case.
        """
        result = run_command(["data", "magic"], {"value": "plain english words"})

        assert result.exit_code == 0
        assert result.parsed["decoded"] is None


class TestResult:
    def test_summary_includes_exit_code(self, tmp_path):
        target = tmp_path / "s.txt"
        target.write_text("x")
        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert "exit 0" in result.summary()
