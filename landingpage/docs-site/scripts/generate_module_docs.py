#!/usr/bin/env python3
"""
Generate MkDocs module documentation from BSOT CLI and enrichment files.

This script:
1. Exports CLI structure via introspection
2. Loads enrichment YAML files for extended documentation
3. Generates Markdown documentation for each module
"""

import json
import sys
from pathlib import Path

import yaml

# Paths
SCRIPT_DIR = Path(__file__).parent
DOCS_SITE_DIR = SCRIPT_DIR.parent
ENRICHMENT_DIR = DOCS_SITE_DIR / "enrichment"
DOCS_DIR = DOCS_SITE_DIR / "docs" / "modules"

# Add the parent directory to the path so we can import bsot
sys.path.insert(0, str(DOCS_SITE_DIR.parent))


def load_enrichment(module_name: str) -> dict:
    """Load enrichment YAML for a module."""
    yaml_path = ENRICHMENT_DIR / f"{module_name}.yaml"
    if yaml_path.exists():
        return yaml.safe_load(yaml_path.read_text()) or {}
    return {}


def format_param(param: dict) -> str:
    """Format a parameter for documentation."""
    if param["type"] == "option":
        opts = ", ".join(f"`{o}`" for o in param.get("opts", []))
        help_text = param.get("help", "")
        default = param.get("default")
        if default is not None:
            help_text += f" (default: `{default}`)"
        return f"| {opts} | {help_text} |"
    else:
        name = f"`{param['name'].upper()}`"
        help_text = param.get("help", "")
        required = "Required" if param.get("required") else "Optional"
        return f"| {name} | {help_text} | {required} |"


def generate_command_docs(cmd: dict, enrichment: dict = None) -> str:
    """Generate documentation for a single command."""
    enrichment = enrichment or {}
    
    lines = []
    lines.append(f"### {cmd['name']}")
    lines.append("")
    
    # Description from enrichment or CLI help
    description = enrichment.get("description", cmd.get("help", ""))
    if description:
        lines.append(description)
        lines.append("")
    
    # Usage
    lines.append("**Usage:**")
    lines.append("")
    lines.append("```bash")
    # Build usage string
    usage_parts = ["bsot", cmd.get("parent", ""), cmd["name"]]
    usage_parts = [p for p in usage_parts if p]
    
    # Add arguments
    args = [p for p in cmd.get("params", []) if p["type"] == "argument"]
    for arg in args:
        if arg.get("required"):
            usage_parts.append(f"<{arg['name'].upper()}>")
        else:
            usage_parts.append(f"[{arg['name'].upper()}]")
    
    lines.append(" ".join(usage_parts) + " [OPTIONS]")
    lines.append("```")
    lines.append("")
    
    # Arguments
    args = [p for p in cmd.get("params", []) if p["type"] == "argument"]
    if args:
        lines.append("**Arguments:**")
        lines.append("")
        lines.append("| Argument | Description | Required |")
        lines.append("|----------|-------------|----------|")
        for arg in args:
            lines.append(format_param(arg))
        lines.append("")
    
    # Options
    opts = [p for p in cmd.get("params", []) if p["type"] == "option"]
    if opts:
        lines.append("**Options:**")
        lines.append("")
        lines.append("| Option | Description |")
        lines.append("|--------|-------------|")
        for opt in opts:
            lines.append(format_param(opt))
        lines.append("")
    
    # Examples from enrichment
    examples = enrichment.get("examples", [])
    if examples:
        lines.append("**Examples:**")
        lines.append("")
        for example in examples:
            title = example.get("title", "Example")
            code = example.get("code", "")
            output = example.get("output", "")
            
            lines.append(f"=== \"{title}\"")
            lines.append("")
            lines.append("    ```bash")
            lines.append(f"    {code}")
            lines.append("    ```")
            lines.append("")
            if output:
                lines.append("    ??? example \"Output\"")
                lines.append("        ```")
                for line in output.split("\n"):
                    lines.append(f"        {line}")
                lines.append("        ```")
                lines.append("")
    
    # Tips from enrichment
    tips = enrichment.get("tips", [])
    if tips:
        lines.append("!!! tip")
        for tip in tips:
            lines.append(f"    {tip}")
        lines.append("")
    
    # Warnings from enrichment
    warnings = enrichment.get("warnings", [])
    if warnings:
        lines.append("!!! warning")
        for warning in warnings:
            lines.append(f"    {warning}")
        lines.append("")
    
    return "\n".join(lines)


def generate_module_docs(module_name: str, module_data: dict) -> str:
    """Generate documentation for an entire module."""
    enrichment = load_enrichment(module_name)
    
    lines = []
    lines.append(f"# {module_name.title()}")
    lines.append("")
    
    # Module description
    description = enrichment.get("description", module_data.get("help", ""))
    if description:
        lines.append(description)
        lines.append("")
    
    lines.append("---")
    lines.append("")
    
    # Commands
    if module_data.get("type") == "group" and module_data.get("commands"):
        lines.append("## Commands")
        lines.append("")
        
        for cmd_name, cmd_data in module_data["commands"].items():
            cmd_data["parent"] = module_name
            cmd_enrichment = enrichment.get("commands", {}).get(cmd_name, {})
            lines.append(generate_command_docs(cmd_data, cmd_enrichment))
            lines.append("---")
            lines.append("")
    
    # Related commands from enrichment
    related = enrichment.get("related", [])
    if related:
        lines.append("## Related Commands")
        lines.append("")
        for rel in related:
            lines.append(f"- `{rel}`")
        lines.append("")
    
    return "\n".join(lines)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate module documentation")
    parser.add_argument("-m", "--module", help="Generate for specific module only")
    parser.add_argument("--dry-run", action="store_true", help="Print instead of writing")
    args = parser.parse_args()
    
    # Import and export CLI
    try:
        from export_docs import export_cli
    except ImportError:
        print("Error: Could not import export_docs", file=sys.stderr)
        sys.exit(1)
    
    cli_data = export_cli()
    
    # Get modules (top-level groups)
    if cli_data.get("type") == "group":
        modules = cli_data.get("commands", {})
    else:
        print("Error: Expected CLI to be a group", file=sys.stderr)
        sys.exit(1)
    
    # Filter to specific module if requested
    if args.module:
        if args.module in modules:
            modules = {args.module: modules[args.module]}
        else:
            print(f"Error: Module '{args.module}' not found", file=sys.stderr)
            sys.exit(1)
    
    # Generate docs for each module
    for module_name, module_data in modules.items():
        # Skip utility modules
        if module_name in ("config", "cache"):
            continue
        
        print(f"Generating docs for {module_name}...")
        
        content = generate_module_docs(module_name, module_data)
        
        if args.dry_run:
            print(content)
            print("-" * 40)
        else:
            output_path = DOCS_DIR / f"{module_name}.md"
            output_path.write_text(content)
            print(f"  Wrote {output_path}")
    
    print("Done!")


if __name__ == "__main__":
    main()

