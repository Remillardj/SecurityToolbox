"""
Run BSOT commands as subprocesses.

Shelling out rather than importing in-process keeps the tested JSON contract as
the interface, stops a crashing command from taking the agent down, and
preserves exit codes (0 clean, 1 findings, 2 error).

Argument rendering is driven entirely by the `_params` metadata that
`bsot.agent.bridge.command_to_schema` captures from the real Click Parameter
objects (see that module for why). Turning a tool-input key into `--key`
by string substitution cannot represent a positional argument (there is no
flag at all) or a renamed option (the Click param name and the flag text can
differ, e.g. `input_file` backed by `--file`), so this module never guesses
from the key name - it only ever does what the metadata says.
"""

import json
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

DEFAULT_TIMEOUT = 300


@dataclass
class CommandResult:
    """Outcome of one command invocation."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    parsed: Optional[Any] = None
    error: str = ""

    def summary(self) -> str:
        return f"{self.command} -> exit {self.exit_code}"


@lru_cache(maxsize=1)
def _catalogue():
    """The tool catalogue, built once and cached for the process lifetime."""
    from .bridge import build_catalogue

    return build_catalogue()


def _lookup_tool(path: Sequence[str]) -> Optional[Dict[str, Any]]:
    """Find the catalogue entry for a command path, or None if unknown."""
    path = list(path)
    for tool in _catalogue():
        if tool["_command_path"] == path:
            return tool
    return None


def _resolve_binary() -> str:
    """
    Find the `bsot` binary to run.

    `shutil.which("bsot")` alone is not safe here: a stale frozen build can sit
    earlier on PATH than this repo's editable install (observed: a v2.0.1
    build at ~/.local/bin/bsot vs. this checkout's v2.1.0), and the stale
    build is missing commands that exist in this tree. The interpreter running
    this process is unambiguous about which install it belongs to, so look for
    a `bsot` next to `sys.executable` first.
    """
    sibling = Path(sys.executable).parent / "bsot"
    if sibling.exists():
        return str(sibling)

    found = shutil.which("bsot")
    if found:
        return found

    return "bsot"


def _is_variadic(meta: Dict[str, Any]) -> bool:
    return bool(meta.get("multiple")) or meta.get("nargs") == -1


def _render_args(
    params: Dict[str, Any], param_meta: Dict[str, Any]
) -> Tuple[List[str], List[str]]:
    """
    Turn tool input into real CLI arguments, driven by `_params` metadata.

    Returns (argv_parts, unknown_keys). `argv_parts` is positionals first (in
    the command's declaration order), then options. `unknown_keys` lists any
    key in `params` that has no entry in `param_meta` at all - those are never
    guessed into a flag; the caller decides how to surface them.
    """
    positional: List[str] = []
    options: List[str] = []

    unknown = [key for key in params if key not in param_meta]

    # Iterate the metadata's order (the command's real declaration order),
    # not the caller's dict order, so multiple positionals (e.g. `data
    # encode ENCODING VALUE`) come out in the right sequence regardless of
    # what order the model supplied them in.
    for name, meta in param_meta.items():
        if name not in params:
            continue
        value = params[name]
        if value is None:
            continue

        if meta["kind"] == "argument":
            if _is_variadic(meta):
                items = value if isinstance(value, (list, tuple)) else [value]
                positional.extend(str(item) for item in items)
            else:
                positional.append(str(value))
            continue

        # kind == "option"
        opt = meta["opt"]
        if meta.get("is_flag"):
            if value:
                options.append(opt)
            else:
                secondary = meta.get("secondary_opt")
                if secondary:
                    options.append(secondary)
                # No secondary flag exists: Click has no `--flag=false`, so a
                # false value with nothing to invert is simply absent.
        elif _is_variadic(meta):
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                options.extend([opt, str(item)])
        else:
            options.extend([opt, str(value)])

    return positional + options, unknown


def run_command(
    path: Sequence[str],
    params: Dict[str, Any],
    param_meta: Optional[Dict[str, Any]] = None,
    supports_json: Optional[bool] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> CommandResult:
    """
    Run `bsot <path> ...` and capture the result.

    `param_meta` and `supports_json` normally come from the tool's catalogue
    entry (`tool["_params"]` / `tool["_supports_json"]` from
    `bsot.agent.bridge`). The runtime (Task 10) already holds the catalogue
    and should pass these straight through. When either is omitted, this
    function looks the command up in the catalogue itself as a convenience -
    useful for direct calls and tests. A command not found in the catalogue
    gets empty metadata and no --json (safer than guessing), and still runs:
    the resulting Click error (e.g. "No such command") is itself useful
    output.
    """
    params = params or {}

    if param_meta is None or supports_json is None:
        tool = _lookup_tool(path)
        if param_meta is None:
            param_meta = tool["_params"] if tool else {}
        if supports_json is None:
            supports_json = tool["_supports_json"] if tool else False

    rendered_args, unknown = _render_args(params, param_meta)

    binary = _resolve_binary()
    argv = [binary, *path, *rendered_args]
    display_argv = ["bsot", *path, *rendered_args]
    if supports_json:
        argv.append("--json")
        display_argv.append("--json")

    command_str = " ".join(shlex.quote(part) for part in display_argv)

    error_notes: List[str] = []
    if unknown:
        error_notes.append(
            "unknown parameter(s) not in tool metadata, skipped rather than "
            "guessed into a flag: " + ", ".join(sorted(unknown))
        )

    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=command_str,
            exit_code=124,
            stdout="",
            stderr="",
            error=f"timed out after {timeout}s",
        )
    except (OSError, FileNotFoundError) as e:
        return CommandResult(
            command=command_str, exit_code=127, stdout="", stderr="", error=str(e)
        )

    result = CommandResult(
        command=command_str,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )

    if completed.stdout.strip():
        try:
            result.parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            # Not every command emits JSON on every path (and some commands
            # have no --json at all); the raw text is still useful.
            pass

    if completed.returncode not in (0, 1):
        stderr_excerpt = completed.stderr.strip()[:500]
        if stderr_excerpt:
            error_notes.append(stderr_excerpt)

    if error_notes:
        result.error = "; ".join(error_notes)

    return result
