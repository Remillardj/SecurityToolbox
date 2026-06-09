#!/usr/bin/env python3
"""
Export BSOT CLI documentation as JSON.

This script introspects the BSOT CLI and exports all commands,
arguments, and options as structured JSON for documentation generation.
"""

import json
import sys
from pathlib import Path

# Add the parent directory to the path so we can import bsot
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import click


def export_command(cmd, name: str = None) -> dict:
    """Export a Click command to a dictionary."""
    result = {
        "name": name or cmd.name,
        "help": cmd.help or "",
        "deprecated": getattr(cmd, "deprecated", False),
    }

    # Handle groups
    if isinstance(cmd, click.Group):
        result["type"] = "group"
        result["commands"] = {}
        for cmd_name, subcmd in cmd.commands.items():
            result["commands"][cmd_name] = export_command(subcmd, cmd_name)
    else:
        result["type"] = "command"

    # Export parameters (arguments and options)
    result["params"] = []
    for param in cmd.params:
        param_info = {
            "name": param.name,
            "type": type(param).__name__.lower(),
            "required": param.required,
            "help": getattr(param, "help", "") or "",
        }

        if isinstance(param, click.Option):
            param_info["opts"] = param.opts
            param_info["is_flag"] = param.is_flag
            param_info["multiple"] = param.multiple
            if param.default is not None and param.default != ():
                param_info["default"] = param.default
            if param.type and hasattr(param.type, "name"):
                param_info["param_type"] = param.type.name
        elif isinstance(param, click.Argument):
            if hasattr(param.type, "name"):
                param_info["param_type"] = param.type.name

        result["params"].append(param_info)

    return result


def export_cli() -> dict:
    """Export the entire BSOT CLI structure."""
    try:
        from bsot import cli
    except ImportError:
        print("Error: Could not import bsot. Make sure it's installed.", file=sys.stderr)
        sys.exit(1)

    return export_command(cli, "bsot")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Export BSOT CLI documentation")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON")
    args = parser.parse_args()

    cli_data = export_cli()

    indent = 2 if args.pretty else None
    json_output = json.dumps(cli_data, indent=indent, default=str)

    if args.output:
        Path(args.output).write_text(json_output)
        print(f"Exported to {args.output}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()

