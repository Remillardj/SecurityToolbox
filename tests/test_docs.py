"""Documentation tests.

The README previously documented an entire CLI that no longer existed
(`bsot file permissions`, `bsot network port-scan`, `bsot data url-decode`),
because nothing tied the docs to the code. These tests fail when they drift.
"""

import re
from pathlib import Path

import pytest

from bsot.cli import cli, get_lazy_plugins

REPO_ROOT = Path(__file__).resolve().parent.parent


def documented_commands(path: Path):
    """Extract `bsot <group> <command>` references from a markdown file."""
    text = path.read_text()
    found = set()
    for match in re.finditer(r'\bbsot\s+([a-z-]+)\s+([a-z][a-z0-9-]*)', text):
        group, command = match.groups()
        # Skip flags and prose that happens to follow the group name.
        if command.startswith('-'):
            continue
        found.add((group, command))
    return found


def real_commands():
    """Every (group, command) pair the CLI actually exposes."""
    pairs = set()
    for name, group in get_lazy_plugins():
        for command in group._load().list_commands(None):
            pairs.add((name, command))
    for group_name in ('config', 'cache'):
        group = cli.commands[group_name]
        for command in group.list_commands(None):
            pairs.add((group_name, command))
    return pairs


# Words that read as commands but are prose, options, or shell noise.
NOT_COMMANDS = {
    ('config', 'set'), ('config', 'create-profile'),
    ('intel', 'enrich'),  # present, but also appears in prose; kept explicitly
}


@pytest.mark.parametrize("doc", ["README.md", "PROJECT_SUMMARY.md"])
def test_documented_commands_exist(doc):
    path = REPO_ROOT / doc
    if not path.exists():
        pytest.skip(f"{doc} not present")

    real = real_commands()
    groups = {group for group, _ in real}

    missing = []
    for group, command in sorted(documented_commands(path)):
        if group not in groups:
            continue  # not a command group reference
        if (group, command) not in real:
            missing.append(f"{group} {command}")

    assert not missing, f"{doc} documents commands that do not exist: {missing}"


def test_readme_covers_every_group():
    readme = (REPO_ROOT / "README.md").read_text()
    for name, _ in get_lazy_plugins():
        assert f"bsot {name}" in readme, f"README does not mention the '{name}' group"


def test_readme_python_version_matches_packaging():
    readme = (REPO_ROOT / "README.md").read_text()
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()

    declared = re.search(r'requires-python\s*=\s*">=(\d+\.\d+)"', pyproject)
    assert declared, "pyproject.toml has no requires-python"

    assert declared.group(1) in readme, (
        f"README does not state the supported Python version ({declared.group(1)})"
    )
