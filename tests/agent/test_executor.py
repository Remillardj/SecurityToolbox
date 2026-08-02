"""
Tests for the bsot subprocess executor.

These are contract tests against the real `bsot` binary - no mocks - because
the whole point of this module is that the JSON contract and the argv shape
are the tested interface. Every case here was verified against the actual
command's behavior first (see the executor-implementation report); where the
plan's assumptions about a command's exit code turned out wrong, the test
asserts what the command actually does.

A handful of cases (timeout, signal death, missing binary, huge output) need
a child process with a specific, deterministic failure mode that no real
bsot command reliably exhibits offline. For those, `_write_script` drops a
tiny standalone executable into `tmp_path` and `monkeypatch` redirects
`executor._resolve_binary()` to it - the subprocess machinery in
`run_command` itself is never mocked, only which binary it is told to run.
"""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import bsot.agent.executor as executor
from bsot.agent.executor import CommandResult, run_command

# tests/agent/test_executor.py -> tests/agent -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_script(tmp_path, name, body):
    """Drop a small standalone executable script into tmp_path."""
    script = tmp_path / name
    script.write_text(body)
    script.chmod(0o755)
    return script


def _nested_env(**overrides):
    """
    Env for a nested `sys.executable` interpreter that must load *this*
    working tree's `bsot`, not whatever `bsot` package happens to be
    resolvable elsewhere on the child's default sys.path (e.g. a
    non-editable install in site-packages). Prepending the repo root to
    PYTHONPATH makes that explicit rather than relying on ambient editable-
    install behavior, which a test spawning a real subprocess should not
    assume: a test that can only fail in one specific dev environment is
    worse than no test.
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        str(REPO_ROOT) if not existing else str(REPO_ROOT) + os.pathsep + existing
    )
    env.update(overrides)
    return env


class TestRunCommand:
    def test_runs_a_read_only_command(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert result.exit_code == 0
        assert result.parsed is not None

    def test_parses_json_output(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert isinstance(result.parsed, list)
        assert "hashes" in result.parsed[0]

    def test_records_the_rendered_command(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert "file hash" in result.command
        assert "--json" in result.command

    def test_missing_command_is_reported(self):
        result = run_command(["file", "no-such-command"], {})

        assert result.exit_code != 0
        assert result.error

    # -- Positional arguments: the case the plan's key-name guessing broke.
    # `intel defang` takes IOC as a bare positional; the plan's _render_args
    # would have turned it into a nonexistent `--ioc` flag.

    def test_positional_argument_command_works(self):
        result = run_command(["intel", "defang"], {"ioc": "1.2.3.4"})

        assert result.exit_code == 0
        assert "--ioc" not in result.command
        assert "1[.]2[.]3[.]4" in result.stdout

    def test_command_without_json_support_gets_no_json_flag(self):
        """intel defang has no --json option; appending one exits 2, not 0."""
        result = run_command(["intel", "defang"], {"ioc": "8.8.8.8"})

        assert "--json" not in result.command
        assert result.exit_code == 0

    # -- Renamed options: the Click param name and the real flag can differ.
    # `data magic`'s Click param is `input_file`, backed by `--file`.

    def test_renamed_option_round_trips(self, tmp_path):
        encoded = tmp_path / "encoded.txt"
        encoded.write_text("SGVsbG8gV29ybGQ=")

        result = run_command(["data", "magic"], {"input_file": str(encoded)})

        assert "--file" in result.command
        assert "--input-file" not in result.command
        assert result.exit_code == 0
        assert result.parsed["decoded"] == "Hello World"

    # -- Multiple positionals keep declaration order.
    # `data encode` is `@click.argument('encoding')` then
    # `@click.argument('value', ...)` (bsot/data/cli.py); the rendered
    # command must put ENCODING before VALUE regardless of dict order.

    def test_multiple_positionals_keep_declaration_order(self):
        result = run_command(
            ["data", "encode"],
            # Deliberately supplied out of declaration order.
            {"value": "Hello World", "encoding": "base64"},
        )

        assert result.exit_code == 0
        assert result.stdout.strip() == "SGVsbG8gV29ybGQ="
        idx_encoding = result.command.index("base64")
        idx_value = result.command.index("Hello World")
        assert idx_encoding < idx_value

    # -- multiple=True options repeat the flag once per item.
    # `file baseline --exclude` is declared with multiple=True.

    def test_multiple_option_repeats_the_flag(self, tmp_path):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "keep.txt").write_text("x")
        output = tmp_path / "baseline.json"

        result = run_command(
            ["file", "baseline"],
            {
                "directory": str(src_dir),
                "output": str(output),
                "exclude": ["*.log", "*.tmp"],
            },
        )

        assert result.exit_code == 0
        assert result.command.count("--exclude") == 2
        assert "*.log" in result.command
        assert "*.tmp" in result.command
        assert output.exists()

    # -- Negative toggle: a False flag with a --no-x counterpart must emit
    # the secondary flag, not just be omitted.

    def test_negative_toggle_emits_secondary_opt(self, tmp_path):
        target_dir = tmp_path / "scan"
        target_dir.mkdir()
        bad_file = target_dir / "bad.txt"
        bad_file.write_text("x")
        os.chmod(bad_file, 0o666)  # world-writable: a real finding

        result = run_command(
            ["file", "permissions"],
            {"directory": str(target_dir), "recursive": False},
        )

        assert "--no-recursive" in result.command
        assert "--recursive" not in result.command
        assert result.exit_code == 1
        assert result.parsed["risky_count"] == 1

    # -- shlex quoting: a path with a space must render quoted, not naively
    # space-joined (a naive join would produce a misleading, non-copy-pasteable
    # provenance string).

    def test_command_with_space_in_path_is_shlex_quoted(self, tmp_path):
        spacey_dir = tmp_path / "dir with space"
        spacey_dir.mkdir()
        encoded = spacey_dir / "enc file.txt"
        encoded.write_text("SGVsbG8gV29ybGQ=")

        result = run_command(["data", "magic"], {"input_file": str(encoded)})

        assert result.exit_code == 0
        # shlex.quote wraps a value containing spaces in single quotes; a
        # naive " ".join would leave it bare and unparseable if copy-pasted.
        assert f"'{encoded}'" in result.command

    # -- Unknown params must never be silently turned into a flag.

    def test_unknown_param_is_surfaced_not_guessed_into_a_flag(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(
            ["file", "hash"],
            {"files": [str(target)], "totally_unknown_param": "x"},
        )

        assert "--totally-unknown-param" not in result.command
        assert "totally_unknown_param" in result.error
        # The known, valid params still run the command normally.
        assert result.exit_code == 0

    # -- Exit code 1 (findings) is returned, never raised. Verified against a
    # command that genuinely exits 1 with --json still attached: `data magic`
    # on non-decodable input does NOT exit 1 once --json is passed (verified
    # separately - see below), so this uses `file permissions` finding a
    # real world-writable file instead.

    def test_nonzero_exit_is_returned_not_raised(self, tmp_path):
        target_dir = tmp_path / "scan2"
        target_dir.mkdir()
        bad_file = target_dir / "bad.txt"
        bad_file.write_text("x")
        os.chmod(bad_file, 0o666)

        result = run_command(["file", "permissions"], {"directory": str(target_dir)})

        assert result.exit_code == 1
        assert isinstance(result, CommandResult)

    def test_data_magic_with_json_does_not_exit_1_on_no_match(self):
        """
        Deviation from the plan: the plan used `data magic` on plain text as
        its exit-1 example. With --json attached (which the executor always
        does when supports_json is true), `bsot/data/cli.py`'s magic command
        takes the `if json_output:` branch unconditionally and returns 0,
        emitting `{"decoded": null, ...}` rather than exiting 1. Documented
        here as a regression guard rather than relied on for the exit-1 case.
        """
        result = run_command(["data", "magic"], {"value": "plain english words"})

        assert result.exit_code == 0
        assert result.parsed["decoded"] is None

    def test_json_not_parsed_when_command_has_no_json_support(self):
        """
        `intel defang 123` prints the bare string "123" to stdout, which
        json.loads happily turns into the int 123 - a bogus "parsed" value
        for a command whose actual output contract is plain text. Parsing
        must be gated on supports_json, not merely "does stdout look like
        JSON".
        """
        result = run_command(["intel", "defang"], {"ioc": "123"})

        assert result.exit_code == 0
        assert result.parsed is None


class TestFlagRendering:
    """
    `is_flag` params must only ever be driven by real booleans. A model
    tool-call error - the string "false" (truthy in Python), 0, "", or [] -
    must never be interpreted via truthiness: that turned `phishing url
    {"expand": "false"}` into a live HTTP request to an attacker-supplied
    URL in the reviewed build, and turned a falsy-but-not-False value into
    the *negative* flag on commands that have one.
    """

    def test_true_emits_the_opt(self):
        result = run_command(
            ["data", "magic"], {"value": "SGVsbG8gV29ybGQ=", "steps": True}
        )

        assert "--steps" in result.command
        assert result.exit_code == 0

    def test_flag_omitted_when_not_supplied_at_all(self):
        result = run_command(["data", "magic"], {"value": "SGVsbG8gV29ybGQ="})

        assert "--steps" not in result.command
        assert result.exit_code == 0

    def test_false_with_no_secondary_opt_is_simply_omitted(self):
        """`--steps` has no `--no-steps`; Click has no `--flag=false`."""
        result = run_command(
            ["data", "magic"], {"value": "SGVsbG8gV29ybGQ=", "steps": False}
        )

        assert "--steps" not in result.command
        assert "--no-steps" not in result.command
        assert result.exit_code == 0

    def test_string_false_is_rejected_not_truthy_coerced_into_on(self):
        result = run_command(
            ["data", "magic"], {"value": "SGVsbG8gV29ybGQ=", "steps": "false"}
        )

        assert "--steps" not in result.command
        assert "steps" in result.error
        assert result.exit_code == 0

    def test_falsy_non_bool_is_rejected_not_flipped_to_the_negative_flag(
        self, tmp_path
    ):
        """
        `file permissions` has a real --no-recursive. 0 is falsy but not
        `False`; it must be rejected, not silently rendered as --no-recursive
        (which would flip the scan's behavior based on a type confusion, not
        a real change of intent).
        """
        target_dir = tmp_path / "scan3"
        target_dir.mkdir()

        result = run_command(
            ["file", "permissions"], {"directory": str(target_dir), "recursive": 0}
        )

        assert "--no-recursive" not in result.command
        assert "--recursive" not in result.command
        assert "recursive" in result.error


class TestPositionalSafety:
    """
    A `--` must separate options from positionals: without it, Click parses
    any positional value starting with `-` as an option, so a model-supplied
    value like `--output=/tmp/pwned.json` gets consumed as a real option
    instead of the literal argument value it's supposed to be.
    """

    def test_dash_leading_positional_value_is_accepted_as_a_value(self):
        """Without `--`, Click rejects this outright ("No such option '-1'")."""
        result = run_command(["intel", "defang"], {"ioc": "-1.2.3.4"})

        assert result.exit_code == 0
        assert result.stdout.strip() == "-1.2.3.4"

    def test_option_shaped_positional_value_is_not_parsed_as_an_option(self):
        """
        A positional value that looks exactly like a different real option
        for this command must be treated as data, not consumed as --file.
        """
        result = run_command(["data", "magic"], {"value": "--file=/etc/hosts"})

        assert result.exit_code == 0
        assert result.parsed["input"] == "--file=/etc/hosts"

    def test_zero_positional_command_is_unaffected(self, tmp_path):
        """A `--` must not appear when there is nothing positional to guard."""
        log = tmp_path / "z.log"
        log.write_text("hello\n")

        result = run_command(["logs", "stats"], {"input_file": str(log)})

        assert result.exit_code == 0
        assert "--" not in shlex.split(result.command)


class TestProvenance:
    """
    `.command` becomes `Finding.source_command` and lands in incident
    reports; it must reproduce exactly what ran, not a generic "bsot" that
    PATH might resolve to a different (possibly stale) binary than the one
    actually executed.
    """

    def test_command_uses_the_resolved_binary_not_a_bare_bsot(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        resolved = executor._resolve_binary()
        assert shlex.split(result.command)[0] == resolved

    def test_command_string_replays_to_the_same_output(self, tmp_path):
        """The strongest form of "faithful": pasting it back actually works."""
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})
        assert result.exit_code == 0

        replayed = subprocess.run(
            shlex.split(result.command), capture_output=True, text=True, timeout=30
        )

        assert replayed.returncode == result.exit_code
        assert replayed.stdout == result.stdout


class TestStdinIsolation:
    """
    `malware deobfuscate --stdin` is READ_ONLY-tiered and auto-runs with no
    human approval, even on a tainted run. Without an explicit `stdin=`, the
    child inherits the analyst's terminal: a tainted model could read
    whatever the analyst types next - including their answer to a later
    approval prompt.
    """

    def test_child_does_not_read_the_parent_stdin(self, tmp_path):
        """
        Reproduces the reviewed leak directly, mirroring
        `echo "ANALYST-SECRET-INPUT" | run_command(...)`: pipe real secret
        content into the *calling* process's real (OS-level) stdin, then
        confirm run_command's spawned child never consumes it. Monkeypatching
        `sys.stdin` in this test process would not exercise the bug at all -
        a subprocess inherits the real file descriptor, not Python's
        `sys.stdin` object - so this uses a nested interpreter whose stdin
        we genuinely control via `input=`.
        """
        probe = tmp_path / "probe.py"
        probe.write_text(
            "from bsot.agent.executor import run_command\n"
            "result = run_command(['malware', 'deobfuscate'], {'stdin': True})\n"
            "print('STDOUT<' + result.stdout + '>END')\n"
        )

        completed = subprocess.run(
            [sys.executable, str(probe)],
            input="ANALYST-SECRET-INPUT\n",
            capture_output=True,
            text=True,
            env=_nested_env(),
            timeout=30,
        )

        assert "ANALYST-SECRET-INPUT" not in completed.stdout
        assert "ANALYST-SECRET-INPUT" not in completed.stderr

    def test_child_gets_immediate_eof_rather_than_blocking(self):
        """
        Before the fix this blocks for up to DEFAULT_TIMEOUT reading the
        (idle) parent TTY's stdin. A short explicit timeout proves it
        returns quickly instead of hanging.
        """
        result = run_command(
            ["malware", "deobfuscate"], {"stdin": True}, timeout=10
        )

        assert result.exit_code != 0  # no content on the (DEVNULL) stdin
        assert result.exit_code != 124  # and it did not have to time out to get there


class TestEncodingSafety:
    def test_non_ascii_output_does_not_raise_under_a_strict_locale(self, tmp_path):
        """
        `text=True` decodes using the parent interpreter's locale-derived
        encoding; under a C/POSIX locale (Docker, cron, systemd, CI often
        run this way) that encoding is ASCII, and the first non-ASCII byte
        raises UnicodeDecodeError - breaking run_command's never-raise
        contract. The encoding is fixed at interpreter startup, so this is
        reproduced by running run_command inside a *child* interpreter
        forced into the C locale, not by mutating this test process's own
        environment.
        """
        probe = tmp_path / "probe.py"
        # base64 of "café ☃" (UTF-8): a real non-ASCII byte sequence
        # produced by a real, offline bsot command (`data decode`).
        probe.write_text(
            "import sys, json\n"
            "from bsot.agent.executor import run_command\n"
            "result = run_command(['data', 'decode'], "
            "{'encoding': 'base64', 'value': 'Y2Fmw6kg4piD'})\n"
            "out = {'exit_code': result.exit_code, 'error': result.error}\n"
            "sys.stdout.buffer.write(json.dumps(out).encode('ascii'))\n"
        )

        completed = subprocess.run(
            [sys.executable, str(probe)],
            capture_output=True,
            text=True,
            env=_nested_env(LC_ALL="C", LANG="C", PYTHONUTF8="0"),
            timeout=30,
        )

        assert "UnicodeDecodeError" not in completed.stderr, completed.stderr
        assert completed.returncode == 0, completed.stderr
        payload = json.loads(completed.stdout)
        assert payload["exit_code"] == 0


class TestOutputBounds:
    def test_large_stdout_is_truncated_with_a_marker(self, tmp_path, monkeypatch):
        script = _write_script(
            tmp_path,
            "big_output.py",
            "#!/usr/bin/env python3\n"
            "import sys\n"
            'sys.stdout.write(\'["\' + "A" * 300000 + \'"]\')\n',
        )
        monkeypatch.setattr(executor, "_resolve_binary", lambda: str(script))

        result = run_command([], {}, param_meta={}, supports_json=True)

        assert result.exit_code == 0
        assert len(result.stdout) < 300000
        assert "truncated" in result.stdout
        assert result.truncated is True
        # A truncated stream is never valid JSON; parsing must not be
        # attempted (and must not silently hand back a mangled structure).
        assert result.parsed is None

    def test_timeout_path_is_bounded_too(self, tmp_path, monkeypatch):
        """
        Regression: `_truncate` was only ever applied after a normal
        `subprocess.run` return, not in the `TimeoutExpired` branch. A
        command with no inherent output bound (the case the cap exists for
        in the first place) is also the one most likely to run out the
        clock: flood stdout, then hang. Before the fix this came back with
        the full, uncapped stream and exit_code=124.
        """
        script = _write_script(
            tmp_path,
            "flood_then_hang.py",
            "#!/usr/bin/env python3\n"
            "import sys, time\n"
            'sys.stdout.write("A" * 300000)\n'
            "sys.stdout.flush()\n"
            "time.sleep(5)\n",
        )
        monkeypatch.setattr(executor, "_resolve_binary", lambda: str(script))

        result = run_command([], {}, param_meta={}, supports_json=False, timeout=0.5)

        assert result.exit_code == 124
        assert len(result.stdout) < 300000
        assert "truncated" in result.stdout
        assert result.truncated is True

    def test_normal_small_output_is_not_flagged_truncated(self, tmp_path):
        target = tmp_path / "sample.txt"
        target.write_text("hello")

        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert result.truncated is False


class TestFailureModes:
    def test_timeout_preserves_partial_output(self, tmp_path, monkeypatch):
        script = _write_script(
            tmp_path,
            "die_slow.py",
            "#!/usr/bin/env python3\n"
            "import sys, time\n"
            "print('partial-output-marker')\n"
            "sys.stdout.flush()\n"
            "time.sleep(5)\n",
        )
        monkeypatch.setattr(executor, "_resolve_binary", lambda: str(script))

        result = run_command([], {}, param_meta={}, supports_json=False, timeout=0.5)

        assert result.exit_code == 124
        assert "timed out" in result.error
        assert "partial-output-marker" in result.stdout

    def test_missing_binary_is_127_not_raised(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            executor, "_resolve_binary", lambda: str(tmp_path / "does-not-exist")
        )

        result = run_command([], {}, param_meta={}, supports_json=False)

        assert result.exit_code == 127
        assert result.error

    def test_signal_killed_child_gets_a_labeled_error(self, tmp_path, monkeypatch):
        """
        A segfault or OOM-kill yields a negative returncode with empty
        stdout/stderr. Without a fallback, .error stays "" and a caller
        doing `result.stdout or result.stderr` sees nothing went wrong.
        """
        script = _write_script(
            tmp_path,
            "die_signal.py",
            "#!/usr/bin/env python3\n"
            "import os, signal\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n",
        )
        monkeypatch.setattr(executor, "_resolve_binary", lambda: str(script))

        result = run_command([], {}, param_meta={}, supports_json=False)

        assert result.exit_code < 0
        assert result.error
        assert "signal" in result.error.lower()
        assert not result.stdout and not result.stderr  # the case with no diagnostic

    def test_exit_1_with_stderr_keeps_the_stderr_in_error(self, tmp_path, monkeypatch):
        """
        The prior guard only populated .error for returncode not in (0, 1),
        dropping stderr warnings on a legitimate findings-exit.
        """
        script = _write_script(
            tmp_path,
            "warn_exit1.py",
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stderr.write('warning: something looked odd\\n')\n"
            "sys.exit(1)\n",
        )
        monkeypatch.setattr(executor, "_resolve_binary", lambda: str(script))

        result = run_command([], {}, param_meta={}, supports_json=False)

        assert result.exit_code == 1
        assert "something looked odd" in result.error


class TestCatalogueEnforcement:
    """
    bridge.py's build_catalogue() deliberately excludes config/cache/
    completion/agent from the agent's tool surface. The executor is the
    enforcement point that makes that exclusion mean "does not run" rather
    than "ran with empty/guessed metadata" - the auto-lookup convenience
    path must refuse a path it can't find, not execute it anyway.
    """

    def test_out_of_catalogue_path_is_refused_not_executed(self):
        result = run_command(["config", "show"], {})

        assert result.exit_code == executor.CATALOGUE_REFUSED_EXIT_CODE
        assert result.stdout == ""  # proves it never actually ran
        assert "config" in result.error
        assert "catalogue" in result.error

    def test_explicit_metadata_bypasses_the_catalogue_check(self):
        """Task 10 already holds the catalogue and passes metadata directly."""
        result = run_command(["config", "show"], {}, param_meta={}, supports_json=False)

        assert result.exit_code == 0
        assert "Configuration" in result.stdout


class TestArgRenderingInternals:
    """White-box coverage for _render_args shapes no real bsot command has today."""

    def test_fixed_arity_option_expands_into_separate_tokens(self):
        from bsot.agent.executor import _render_args

        param_meta = {
            "coords": {
                "kind": "option",
                "opt": "--coords",
                "is_flag": False,
                "multiple": False,
                "nargs": 2,
            },
        }

        options, positional, problems = _render_args({"coords": [1, 100]}, param_meta)

        assert options == ["--coords", "1", "100"]
        assert positional == []
        assert problems == []

    def test_lookup_tool_returns_independent_copies(self):
        """A caller mutating one lookup's dict must not poison the shared cache."""
        from bsot.agent.executor import _lookup_tool

        first = _lookup_tool(["file", "hash"])
        first["_params"]["algo"]["opt"] = "POISONED"

        second = _lookup_tool(["file", "hash"])

        assert second["_params"]["algo"]["opt"] != "POISONED"


class TestResult:
    def test_summary_includes_exit_code(self, tmp_path):
        target = tmp_path / "s.txt"
        target.write_text("x")
        result = run_command(["file", "hash"], {"files": [str(target)]})

        assert "exit 0" in result.summary()
