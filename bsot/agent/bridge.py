"""
Generate agent tool schemas from the Click command tree.

Hand-written definitions for 70+ commands would drift from the CLI within a
week. Deriving them from Click means the two cannot disagree by construction.
"""

from typing import Any, Dict, List

import click

# The executor always supplies --json, so the model must not control it.
EXCLUDED_PARAMS = {"json_output", "help"}

# Click type name -> JSON Schema type
_TYPE_MAP = {
    "text": "string",
    "integer": "integer",
    "float": "number",
    "boolean": "boolean",
    "choice": "string",
    "path": "string",
    "file": "string",
}


def _param_schema(param: click.Parameter) -> Dict[str, Any]:
    """Convert one Click parameter to a JSON Schema property."""
    if getattr(param, "is_flag", False):
        prop: Dict[str, Any] = {"type": "boolean"}
    else:
        json_type = _TYPE_MAP.get(param.type.name, "string")
        prop = {"type": json_type}

    if isinstance(param.type, click.Choice):
        prop["enum"] = list(param.type.choices)

    if param.multiple or param.nargs == -1:
        prop = {"type": "array", "items": prop}

    help_text = getattr(param, "help", None)
    if help_text:
        prop["description"] = help_text

    return prop


def command_to_schema(command: click.Command, path: List[str]) -> Dict[str, Any]:
    """Build a tool schema for one Click command."""
    properties: Dict[str, Any] = {}
    required: List[str] = []

    for param in command.params:
        if param.name in EXCLUDED_PARAMS:
            continue
        properties[param.name] = _param_schema(param)
        if param.required:
            required.append(param.name)

    description = command.help or command.get_short_help_str() or " ".join(path)

    return {
        "name": "bsot_" + "_".join(path).replace("-", "_"),
        "description": description.strip(),
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
        # Consumed by the executor and the safety tiering, not sent to the model.
        "_command_path": path,
    }


def _walk(group: click.Group, prefix: List[str], out: List[Dict[str, Any]]) -> None:
    for name in group.list_commands(None):
        command = group.get_command(None, name)
        if command is None:
            continue
        path = prefix + [name]
        if isinstance(command, click.Group):
            _walk(command, path, out)
        else:
            out.append(command_to_schema(command, path))


def build_catalogue() -> List[Dict[str, Any]]:
    """Every BSOT command, as agent tool schemas."""
    from bsot.cli import get_lazy_plugins

    catalogue: List[Dict[str, Any]] = []
    for name, lazy_group in get_lazy_plugins():
        _walk(lazy_group._load(), [name], catalogue)
    return catalogue
