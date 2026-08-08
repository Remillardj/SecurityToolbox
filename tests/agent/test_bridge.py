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

    def test_choice_becomes_enum(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "strings"), ["file", "strings"])

        assert schema["input_schema"]["properties"]["encoding"]["enum"] == [
            "ascii",
            "unicode",
            "both",
        ]

    def test_multiple_becomes_array(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "baseline"), ["file", "baseline"])

        assert schema["input_schema"]["properties"]["exclude"]["type"] == "array"

    def test_variadic_argument_becomes_array(self):
        """`files` is `nargs=-1`, not `multiple=True`; both paths must map to array."""
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])

        assert schema["input_schema"]["properties"]["files"]["type"] == "array"


class TestCommandPathPreservesDashes:
    def test_bulk_block_path_keeps_dash(self, catalogue):
        """Task 3's tiering table keys on dashed paths like ['ir','cf','bulk-block']."""
        tool = next(t for t in catalogue if t["name"] == "bsot_ir_cf_bulk_block")
        assert tool["_command_path"] == ["ir", "cf", "bulk-block"]


class TestParamMetadata:
    """
    `_params` carries what the executor needs to reconstruct argv: whether a
    param is positional or a flag, and its real option string — the Python
    identifier alone isn't enough (positional args have no flag, and some
    options are renamed, e.g. `data magic`'s `input_file` is `--file`).
    """

    def test_argument_kind(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["intel"]._load()
        schema = command_to_schema(group.get_command(None, "defang"), ["intel", "defang"])

        assert schema["_params"]["ioc"]["kind"] == "argument"

    def test_renamed_option_carries_real_flag(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["data"]._load()
        schema = command_to_schema(group.get_command(None, "magic"), ["data", "magic"])

        assert schema["_params"]["input_file"]["kind"] == "option"
        assert schema["_params"]["input_file"]["opt"] == "--file"

    def test_toggle_default_and_secondary_opt(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(
            group.get_command(None, "permissions"), ["file", "permissions"]
        )

        assert schema["input_schema"]["properties"]["recursive"]["default"] is True
        assert schema["_params"]["recursive"]["secondary_opt"] == "--no-recursive"

    def test_multi_positional_order_is_preserved(self):
        """
        The executor renders positional args in `_params` insertion order.
        `data encode` declares `encoding` before `value`
        (bsot/data/cli.py: @click.argument('encoding') then @click.argument('value'));
        a reversed dict would silently render `bsot data encode <value> <encoding>`.
        """
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["data"]._load()
        schema = command_to_schema(group.get_command(None, "encode"), ["data", "encode"])

        argument_keys = [
            name for name, meta in schema["_params"].items() if meta["kind"] == "argument"
        ]
        assert argument_keys == ["encoding", "value"]


class TestArbitraryWritePathStripped:
    """
    `--output` is, uniformly across this codebase, an arbitrary write-target
    path. Agents get stdout JSON; a file redirect is a human affordance and
    must not be model-composable. Stripped only when optional - `file
    baseline` requires it and is gated at the tiering layer instead.
    """

    def test_logs_analyze_has_no_output_property(self, catalogue):
        tool = next(t for t in catalogue if t["name"] == "bsot_logs_analyze")
        assert "output" not in tool["input_schema"]["properties"]
        assert "output" not in tool["_params"]

    def test_file_baseline_still_has_required_output(self, catalogue):
        """Required with no safe default - dropping it would make the tool uncallable."""
        tool = next(t for t in catalogue if t["name"] == "bsot_file_baseline")
        assert "output" in tool["input_schema"]["properties"]
        assert "output" in tool["_params"]
        assert "output" in tool["input_schema"]["required"]


class TestSecretParamsStripped:
    """
    Credentials come from the analyst's config/environment, never
    model-composed argv. The heuristic matches on name (`_key` suffix, or
    named exactly/ending in `password`/`token`/`secret`), with two narrow
    exceptions for params that are credential-shaped by name but are
    actually the artifact under analysis.
    """

    def test_phishing_analyze_has_no_api_key_properties(self, catalogue):
        tool = next(t for t in catalogue if t["name"] == "bsot_phishing_analyze")
        properties = tool["input_schema"]["properties"]
        for key_param in ("openai_key", "anthropic_key", "virustotal_key", "abuseipdb_key"):
            assert key_param not in properties
            assert key_param not in tool["_params"]

    def test_report_package_loses_password(self, catalogue):
        """--password encrypts the output archive - a credential, not an analysis subject."""
        tool = next(t for t in catalogue if t["name"] == "bsot_report_package")
        assert "password" not in tool["input_schema"]["properties"]
        assert "password" not in tool["_params"]

    def test_auth_jwt_decode_keeps_token(self, catalogue):
        """`token` here is the JWT being decoded, not a credential supplied to BSOT."""
        tool = next(t for t in catalogue if t["name"] == "bsot_auth_jwt_decode")
        assert "token" in tool["input_schema"]["properties"]
        assert "token" in tool["_params"]

    def test_auth_password_analyze_keeps_password(self, catalogue):
        """`password` here is the password being scored, not a credential supplied to BSOT."""
        tool = next(t for t in catalogue if t["name"] == "bsot_auth_password_analyze")
        assert "password" in tool["input_schema"]["properties"]
        assert "password" in tool["_params"]


class TestNoRequiredParamIsEverStripped:
    """
    Stripping is only safe when the param is optional (or explicitly
    exempted). If any stripping rule ever removed a *required* param, the
    tool would be uncallable - `required` would name a property that
    doesn't exist. Checked across the whole catalogue, not just the
    commands the other tests target directly.
    """

    def test_every_required_param_has_a_property(self, catalogue):
        offenders = [
            (tool["name"], name)
            for tool in catalogue
            for name in tool["input_schema"]["required"]
            if name not in tool["input_schema"]["properties"]
        ]
        assert not offenders, f"required params missing from properties: {offenders}"


class TestAgentGroupExcluded:
    """
    The agent must never be offered its own command surface - that's
    recursive self-invocation. Task 12 registers an `agent` plugin group
    later; this guards against it leaking into the catalogue.
    """

    def test_no_tool_name_starts_with_bsot_agent(self, catalogue):
        names = [tool["name"] for tool in catalogue]
        offenders = [n for n in names if n.startswith("bsot_agent_")]
        assert not offenders


class TestParamTypeMeta:
    """
    JSON Schema alone can't tell a filesystem-path parameter from plain
    text - `_TYPE_MAP` collapses both Click's `path` and `file` types to
    `"string"`. `_params[...]['type']` carries the real Click type name so
    a downstream consumer (sec-team-mcp) can identify path-typed params
    without importing bsot.
    """

    def test_path_typed_param_reports_path_not_text(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])

        param_type = schema["_params"]["files"]["type"]
        assert param_type in {"path", "file"}
        assert param_type != "text"


class TestSupportsJson:
    def test_true_when_command_has_json_flag(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["file"]._load()
        schema = command_to_schema(group.get_command(None, "hash"), ["file", "hash"])

        assert schema["_supports_json"] is True

    def test_false_when_command_has_no_json_flag(self):
        from bsot.cli import get_lazy_plugins

        group = dict(get_lazy_plugins())["intel"]._load()
        schema = command_to_schema(group.get_command(None, "defang"), ["intel", "defang"])

        assert schema["_supports_json"] is False
