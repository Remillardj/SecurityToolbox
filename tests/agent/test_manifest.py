"""
Tests for the read-only capability manifest external consumers grant from.

Each failure-mode test builds a small, deliberately broken `groups` dict and
passes it directly to `validate_manifest(groups=...)` rather than mutating
the real `GROUPS` - that keeps every test isolated and never leaves a
broken manifest importable by anything else in the suite.
"""

import pytest

from bsot.agent.manifest import GROUPS, ManifestError, validate_manifest


class TestShippedManifest:
    def test_the_shipped_manifest_validates(self):
        """Already ran once at import time (manifest.py's module bottom);
        this makes the guarantee explicit and independently rerunnable."""
        validate_manifest()

    def test_every_group_is_non_empty(self):
        for name, commands in GROUPS.items():
            assert commands, f"group {name!r} declares no commands"


class TestUnknownCommand:
    def test_a_command_path_absent_from_build_catalogue_raises(self):
        groups = {
            "bogus-group": {
                ("not", "a", "real", "command"): (),
            },
        }

        with pytest.raises(ManifestError, match="not in build_catalogue"):
            validate_manifest(groups)


class TestNonReadOnlyCommand:
    def test_a_non_read_only_command_raises(self):
        """`network ports` is EXTERNAL_MUTATION (safety.py); a manifest
        group is a grant of read-only access only."""
        groups = {
            "bogus-group": {
                ("network", "ports"): (),
            },
        }

        with pytest.raises(ManifestError, match="not read_only"):
            validate_manifest(groups)


class TestBogusDeclaredParam:
    def test_a_declared_param_not_on_the_command_raises(self):
        """`file identify` really takes `file_path`, not this name."""
        groups = {
            "bogus-group": {
                ("file", "identify"): ("this_param_does_not_exist",),
            },
        }

        with pytest.raises(ManifestError, match="has no parameter"):
            validate_manifest(groups)


class TestUndeclaredPathParam:
    def test_a_path_shaped_param_left_undeclared_raises(self):
        """
        `logs parse --input-file` is Click type `path`. Declaring the
        command with no path params at all must be rejected - this is the
        symmetric check (validate_manifest's check 4): a forgotten
        declaration would otherwise become an unscoped filesystem read in
        the downstream consumer.
        """
        groups = {
            "bogus-group": {
                ("logs", "parse"): (),
            },
        }

        with pytest.raises(ManifestError, match="not declared as a path"):
            validate_manifest(groups)

    def test_a_file_typed_param_left_undeclared_also_raises(self):
        """Same check, but for a param whose Click type is `file` rather
        than `path` - both are collapsed to JSON Schema `string` and must
        both be caught (see the module docstring's note on `_TYPE_MAP`)."""
        from bsot.agent.bridge import build_catalogue

        file_typed = [
            (tuple(entry["_command_path"]), name)
            for entry in build_catalogue()
            for name, meta in entry["_params"].items()
            if meta.get("type") == "file"
        ]
        if not file_typed:
            pytest.skip("no command currently declares a Click `file` param")

        path, _param_name = file_typed[0]
        groups = {"bogus-group": {path: ()}}

        with pytest.raises(ManifestError, match="not declared as a path"):
            validate_manifest(groups)
