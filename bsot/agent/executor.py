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

import copy
import json
import shlex
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

DEFAULT_TIMEOUT = 300

# A single tool result is one turn of an agent loop's context, not the whole
# budget. 200,000 characters is roughly 50k tokens - already far more than a
# model should spend reading one command's output - while still comfortably
# covering the JSON any well-behaved bsot command emits. Commands with no
# inherent output bound (`file strings` on a large binary) are the case this
# protects against.
MAX_OUTPUT_CHARS = 200_000

# Commands intentionally kept off the agent's tool surface (see
# bsot/agent/bridge.py: config/cache/completion manage local secrets and
# shell setup, and `agent` is the runtime's own surface). A path that
# resolves outside the catalogue must never run just because a caller didn't
# supply metadata - the catalogue is the enforcement point for "the agent may
# only call what bridge.py exposed," not merely a convenience lookup.
CATALOGUE_REFUSED_EXIT_CODE = 126


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
    """
    Find the catalogue entry for a command path, or None if unknown.

    Returns a deep copy: `_catalogue()` is a single `lru_cache`d list shared
    by every call in this process, and a caller that mutates the dict it gets
    back (e.g. edits `param_meta` in place) must not corrupt that shared
    cache for every later lookup.
    """
    path = list(path)
    for tool in _catalogue():
        if tool["_command_path"] == path:
            return copy.deepcopy(tool)
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
) -> Tuple[List[str], List[str], List[str]]:
    """
    Turn tool input into real CLI arguments, driven by `_params` metadata.

    Returns (options, positional, problems).

    - `options` are flags/options in the command's declaration order.
    - `positional` are positional arguments in declaration order. Kept
      separate from `options` (rather than concatenated here) because the
      caller must place a `--` between the two: Click, like any POSIX
      parser, will otherwise happily consume a positional value that starts
      with `-` as an option, or - worse - let a *model-supplied* positional
      value such as `--output=/tmp/pwned.json` be parsed as a real option.
    - `problems` lists anything this function refused to render silently:
      keys with no entry in `param_meta` at all (never guessed into a flag),
      and `is_flag` values that were not real booleans (`"false"`, `0`, `""`
      are common model tool-call errors that must not be interpreted as
      "flag off" via truthiness - that's how `expand: "false"` turned into
      `--expand` firing a live HTTP request in the reviewed build).
    """
    positional: List[str] = []
    options: List[str] = []
    problems: List[str] = []

    unknown = [key for key in params if key not in param_meta]
    if unknown:
        problems.append(
            "unknown parameter(s) not in tool metadata, skipped rather than "
            "guessed into a flag: " + ", ".join(sorted(unknown))
        )

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
            if isinstance(value, bool):
                if value:
                    options.append(opt)
                else:
                    secondary = meta.get("secondary_opt")
                    if secondary:
                        options.append(secondary)
                    # No secondary flag exists: Click has no `--flag=false`,
                    # so a false value with nothing to invert is simply
                    # absent.
            else:
                # A non-boolean for a flag param is never coerced by
                # truthiness: the string "false" is truthy in Python and
                # would otherwise turn the flag ON.
                problems.append(
                    f"parameter {name!r} is a flag and requires true/false, "
                    f"got {value!r} - omitted rather than guessed"
                )
        elif meta.get("nargs", 1) not in (1, -1) and not meta.get("multiple"):
            # Fixed arity > 1 (e.g. nargs=2): expand into that many tokens
            # rather than str()-ing a tuple into one unparseable token. No
            # current bsot param has this shape, but the metadata format
            # allows it.
            items = value if isinstance(value, (list, tuple)) else [value]
            options.append(opt)
            options.extend(str(item) for item in items)
        elif _is_variadic(meta):
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                options.extend([opt, str(item)])
        else:
            options.extend([opt, str(value)])

    return options, positional, problems


def _label_returncode(returncode: int) -> Optional[str]:
    """Describe a signal-killed child; None for a normal (>= 0) exit code."""
    if returncode >= 0:
        return None
    sig = -returncode
    try:
        name = signal.Signals(sig).name
        return f"killed by signal {sig} ({name})"
    except ValueError:
        return f"killed by signal {sig}"


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> Tuple[str, bool]:
    """Cap `text` at `limit` characters, reporting whether it was cut."""
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _decode(maybe_bytes) -> str:
    """TimeoutExpired.stdout/.stderr may be bytes or str depending on platform."""
    if maybe_bytes is None:
        return ""
    if isinstance(maybe_bytes, bytes):
        return maybe_bytes.decode("utf-8", errors="replace")
    return maybe_bytes


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
    and should pass both straight through - when a caller supplies both, this
    function trusts them completely and does not re-check the catalogue.
    When either is omitted, this function looks the command up in the
    catalogue itself as a convenience for direct calls and tests. If that
    lookup fails to find the path, the command is refused outright rather
    than run with guessed-empty metadata and no --json: `bridge.py`
    deliberately excludes `config`/`cache`/`completion`/`agent` from the
    catalogue, and the executor is the layer that has to make that exclusion
    actually mean "does not run" rather than "the agent didn't happen to
    guess flags for it."
    """
    params = params or {}

    if param_meta is None or supports_json is None:
        tool = _lookup_tool(path)
        if tool is None:
            display = " ".join(shlex.quote(p) for p in ["bsot", *path])
            return CommandResult(
                command=display,
                exit_code=CATALOGUE_REFUSED_EXIT_CODE,
                stdout="",
                stderr="",
                error=(
                    f"refusing to run {' '.join(path)!r}: not in the agent "
                    "tool catalogue (build_catalogue() excludes config, "
                    "cache, completion, and agent by design; pass an "
                    "explicit param_meta/supports_json to bypass this "
                    "lookup for a path known to be valid)"
                ),
            )
        if param_meta is None:
            param_meta = tool["_params"]
        if supports_json is None:
            supports_json = tool["_supports_json"]

    options, positional, problems = _render_args(params, param_meta)

    if supports_json:
        options = options + ["--json"]
    # `--` must sit after every option and before the first positional:
    # everything Click sees after it is a positional value, never an option,
    # which is what stops a model-supplied value like "-rf" or
    # "--output=/tmp/pwned.json" from being parsed as a flag.
    rendered_args = options + (["--", *positional] if positional else [])

    binary = _resolve_binary()
    argv = [binary, *path, *rendered_args]
    # The provenance string must reproduce exactly what ran, including the
    # resolved binary - not a bare "bsot" that PATH might resolve to a
    # different (possibly stale) build than the one actually executed.
    command_str = " ".join(shlex.quote(part) for part in argv)

    error_notes: List[str] = list(problems)

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,  # never inherit the analyst's terminal
            errors="replace",  # never raise UnicodeDecodeError under a strict locale
        )
    except subprocess.TimeoutExpired as e:
        # Partial output captured before the kill is still evidence; discard
        # neither stream.
        return CommandResult(
            command=command_str,
            exit_code=124,
            stdout=_decode(e.stdout),
            stderr=_decode(e.stderr),
            error=f"timed out after {timeout}s",
        )
    except (OSError, FileNotFoundError) as e:
        return CommandResult(
            command=command_str, exit_code=127, stdout="", stderr="", error=str(e)
        )

    stdout_text, stdout_truncated = _truncate(completed.stdout)
    stderr_text, stderr_truncated = _truncate(completed.stderr)
    if stdout_truncated:
        stdout_text += (
            f"\n... [truncated: output was {len(completed.stdout)} chars, "
            f"kept first {MAX_OUTPUT_CHARS}]"
        )
    if stderr_truncated:
        stderr_text += (
            f"\n... [truncated: stderr was {len(completed.stderr)} chars, "
            f"kept first {MAX_OUTPUT_CHARS}]"
        )

    result = CommandResult(
        command=command_str,
        exit_code=completed.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
    )

    # Only parse when the command was actually asked for JSON: a plain-text
    # command's stdout can coincidentally be valid JSON (`intel defang 123`
    # emits the bare string "123", which json.loads happily turns into the
    # int 123) - never parsed since it isn't the documented output shape.
    # A truncated stream is never valid JSON, so don't try.
    if supports_json and not stdout_truncated and stdout_text.strip():
        try:
            result.parsed = json.loads(stdout_text)
        except json.JSONDecodeError:
            pass

    signal_label = _label_returncode(completed.returncode)
    if signal_label:
        error_notes.append(signal_label)

    stderr_excerpt = stderr_text.strip()[:500]
    if stderr_excerpt:
        error_notes.append("stderr: " + stderr_excerpt)

    # A caller inspecting `result.stdout or result.stderr` must be able to
    # tell something went wrong even when the child died silently (segfault,
    # OOM-kill) with nothing on either stream.
    if completed.returncode not in (0, 1) and not error_notes:
        error_notes.append(
            f"command exited with code {completed.returncode} and produced "
            "no stdout or stderr"
        )

    if error_notes:
        result.error = "; ".join(error_notes)

    return result
