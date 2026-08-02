"""Tests for Click-to-tool-schema generation."""

import pytest

from bsot.agent.bridge import build_catalogue, command_to_schema


@pytest.fixture(scope="module")
def catalogue():
    return build_catalogue()


class TestCatalogue:
    def test_includes_top_level_commands(self, catalogue):
        names = {tool["name"] for tool in catalogue}
        assert "bsot_file_hash" in names

    def test_recurses_into_nested_groups(self, catalogue):
        """ir cf block is nested; a flat walk would miss it."""
        names = {tool["name"] for tool in catalogue}
        assert "bsot_ir_cf_block" in names

    def test_every_tool_has_required_keys(self, catalogue):
        for tool in catalogue:
            assert tool["name"]
            assert tool["description"]
            assert tool["input_schema"]["type"] == "object"

    def test_names_are_unique(self, catalogue):
        names = [tool["name"] for tool in catalogue]
        assert len(names) == len(set(names))

    def test_carries_the_command_path(self, catalogue):
        tool = next(t for t in catalogue if t["name"] == "bsot_file_hash")
        assert tool["_command_path"] == ["file", "hash"]


class TestSchema:
    def test_flag_becomes_boolean(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])
        properties = schema["input_schema"]["properties"]

        assert properties["recursive"]["type"] == "boolean"

    def test_string_option_becomes_string(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])

        assert schema["input_schema"]["properties"]["algo"]["type"] == "string"

    def test_required_argument_is_required(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])

        assert "files" in schema["input_schema"]["required"]

    def test_json_flag_is_excluded(self):
        """The executor always passes --json; the model must not toggle it."""
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])

        assert "json_output" not in schema["input_schema"]["properties"]
