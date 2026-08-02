"""Smoke tests that every command is importable and its paths execute.

These exist because a NameError inside a command body (a missing `import sys`,
say) surfaces only when that branch runs, and click turns the traceback into
exit code 1 - which is indistinguishable from a normal "findings" exit unless
stderr is inspected.
"""

import pytest
from click.testing import CliRunner

from bsot.cli import cli, get_lazy_plugins


@pytest.fixture
def runner():
    return CliRunner()


def assert_no_crash(result):
    """Fail if the command raised rather than exiting deliberately."""
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise AssertionError(
            f"command raised {type(result.exception).__name__}: {result.exception}"
        )


class TestGroupsLoad:
    @pytest.mark.parametrize("group", [name for name, _ in get_lazy_plugins()])
    def test_group_help_renders(self, runner, group):
        result = runner.invoke(cli, [group, "--help"])

        assert_no_crash(result)
        assert result.exit_code == 0

    def test_top_level_help(self, runner):
        result = runner.invoke(cli, ["--help"])

        assert_no_crash(result)
        assert result.exit_code == 0

    def test_every_subcommand_help_renders(self, runner):
        """Catches syntax and import errors inside individual command bodies."""
        for group_name, group in get_lazy_plugins():
            impl = group._load()
            for cmd_name in impl.list_commands(None):
                result = runner.invoke(cli, [group_name, cmd_name, "--help"])
                assert_no_crash(result)
                assert result.exit_code == 0, f"{group_name} {cmd_name} --help failed"


class TestConfigCheck:
    def test_default_run(self, runner):
        result = runner.invoke(cli, ["config", "check"])
        assert_no_crash(result)

    def test_json_output(self, runner):
        import json

        result = runner.invoke(cli, ["config", "check", "--json"])
        assert_no_crash(result)
        assert "services" in json.loads(result.output)

    def test_unknown_service_exits_2(self, runner):
        result = runner.invoke(cli, ["config", "check", "--service", "nope"])

        assert_no_crash(result)
        assert result.exit_code == 2


class TestCompletion:
    @pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
    def test_emits_script(self, runner, shell):
        result = runner.invoke(cli, ["completion", shell])

        assert_no_crash(result)
        assert result.exit_code == 0
        assert "_BSOT_COMPLETE" in result.output

    def test_rejects_unknown_shell(self, runner):
        result = runner.invoke(cli, ["completion", "tcsh"])
        assert result.exit_code == 2


class TestCacheGroup:
    def test_stats(self, runner):
        result = runner.invoke(cli, ["cache", "stats"])
        assert_no_crash(result)
