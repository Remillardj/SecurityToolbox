"""
Generate agent tool schemas from the Click command tree.

Hand-written definitions for 70+ commands would drift from the CLI within a
week. Deriving them from Click means the two cannot disagree by construction.
"""

from typing import Any, Dict, List

import click

# The executor always supplies --json, so the model must not control it.
# ("help" is not listed here: Click builds the --help option on demand in
# Command.get_params(ctx) and appends it there — it's never stored in
# command.params, which is what this module reads.)
EXCLUDED_PARAMS = {"json_output"}

# Every `--output` option in this codebase is, uniformly, an arbitrary
# write-target path (verified by reading every command that defines one).
# Agents consume stdout JSON; a file redirect is a human affordance, not
# something a model should compose. Stripped only when optional: `file
# baseline` requires it with no safe default, so dropping it there would
# leave the model unable to call the command at all. That command stays
# gated at the tiering layer instead (see bsot/agent/safety.py).
_ARBITRARY_WRITE_PATH_PARAMS = {"output"}


# A credential-shaped name (ends in _key/password/token/secret) is usually
# a secret the analyst configured, never something a model should compose —
# except these two, where the same-shaped name is the artifact under
# analysis rather than a credential: `auth jwt-decode <token>` decodes the
# JWT string itself, and `auth password-analyze <password>` scores the
# password itself. Keyed by (command path, param name) rather than name
# alone so this stays a narrow, auditable exception.
_SECRET_LOOKALIKE_EXEMPTIONS = {
    (("auth", "jwt-decode"), "token"),
    (("auth", "password-analyze"), "password"),
}


def _is_secret_param(path: List[str], name: str) -> bool:
    """
    Credentials come from the analyst's config or environment, never from
    model-composed argv — stripped unconditionally, regardless of whether
    Click marks them required (none currently are; if one ever were, that
    would make the command uncallable via the agent, which is the right
    failure mode for a command whose only interface is a secret).

    Matches API keys (openai_key, anthropic_key, virustotal_key,
    abuseipdb_key, ...) via the `_key` suffix, plus anything named exactly
    or ending in `password`, `token`, or `secret` (e.g. `report package
    --password`, which encrypts the output archive) — except the two
    analysis-subject params in _SECRET_LOOKALIKE_EXEMPTIONS.
    """
    if (tuple(path), name) in _SECRET_LOOKALIKE_EXEMPTIONS:
        return False
    return name.endswith(("_key", "password", "token", "secret"))


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

    # Surface the default for boolean properties (most importantly on
    # --flag/--no-flag toggles) so the model can see what "unset" means
    # instead of guessing.
    if prop.get("type") == "boolean" and isinstance(param.default, bool):
        prop["default"] = param.default

    help_text = getattr(param, "help", None)
    if help_text:
        prop["description"] = help_text

    return prop


def _param_meta(param: click.Parameter) -> Dict[str, Any]:
    """
    Metadata needed to rebuild the real argv for one param.

    JSON Schema only carries the Python identifier (param.name), which is
    not enough to reconstruct a command line: positional arguments have no
    flag at all, and renamed options (e.g. Click param name `input_file`
    backed by `--file`) don't round-trip from the identifier. This is the
    only place that still has the Click Parameter object, so it's the only
    place this can be captured.
    """
    meta: Dict[str, Any] = {
        "kind": "argument" if isinstance(param, click.Argument) else "option",
        "is_flag": bool(getattr(param, "is_flag", False)),
        "multiple": bool(param.multiple),
        "nargs": param.nargs,
    }

    if isinstance(param, click.Option):
        meta["opt"] = next((o for o in param.opts if o.startswith("--")), param.opts[0])
        if param.secondary_opts:
            meta["secondary_opt"] = next(
                (o for o in param.secondary_opts if o.startswith("--")),
                param.secondary_opts[0],
            )

    return meta


def command_to_schema(command: click.Command, path: List[str]) -> Dict[str, Any]:
    """Build a tool schema for one Click command."""
    properties: Dict[str, Any] = {}
    required: List[str] = []
    params_meta: Dict[str, Any] = {}
    supports_json = False

    for param in command.params:
        if param.name == "json_output":
            supports_json = True
        if param.name in EXCLUDED_PARAMS:
            continue
        if param.name in _ARBITRARY_WRITE_PATH_PARAMS and not param.required:
            continue
        if _is_secret_param(path, param.name):
            continue
        properties[param.name] = _param_schema(param)
        params_meta[param.name] = _param_meta(param)
        if param.required:
            required.append(param.name)

    description = command.help or command.get_short_help_str() or " ".join(path)
    # Click's `\b` no-rewrap marker is a literal backspace (0x08) once the
    # docstring is parsed; it has no meaning outside a terminal help page.
    description = description.replace("\x08", "").strip()

    return {
        "name": "bsot_" + "_".join(path).replace("-", "_"),
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
        # Consumed by the executor and the safety tiering, not sent to the
        # model — Task 11 strips every key starting with "_" before the
        # catalogue reaches the model.
        "_command_path": path,
        "_params": params_meta,
        "_supports_json": supports_json,
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
    """
    Every BSOT command, as agent tool schemas.

    Walks only the plugin groups returned by `get_lazy_plugins()` (phishing,
    intel, file, network, logs, data, auth, system, ir, malware, case,
    report, osint). Top-level utility commands defined directly on `cli` in
    bsot/cli.py — `config`, `cache`, `completion` — are deliberately not
    exposed to the agent: they manage local API keys and shell setup rather
    than performing analysis, and aren't commands an agent should be
    invoking on the operator's behalf.
    """
    from bsot.cli import get_lazy_plugins

    catalogue: List[Dict[str, Any]] = []
    for name, lazy_group in get_lazy_plugins():
        # A future `agent` plugin group (the runtime's own command surface)
        # must never be offered back to the agent — that's recursive
        # self-invocation. Skipped by name rather than relying on that
        # group never defining agent-shaped tools.
        if name == "agent":
            continue
        _walk(lazy_group._load(), [name], catalogue)
    return catalogue
