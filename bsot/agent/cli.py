"""
CLI commands for the agent runtime.

`AgentRun` (bsot/agent/runtime.py) exposes more than the plan's original
sketch of this module: `stop_reason`, `error`, and `failed_findings` all
exist to prevent a specific misreading of a run, so all three are rendered
here, not just the plan's `findings`/`pending_approval`/`transcript`.

- `stop_reason` is the important one. A run that hit "max_iterations" was
  cut off mid-investigation; printing it identically to "completed" would
  let an incomplete investigation read as a clean one, so truncation gets
  its own loud banner in the human-readable path (see `_render_status`)
  and is never silently folded into a normal-looking summary.
- `error` is a dict (`phase`, `tool`, `exception_type`, `message`) set only
  when the run ended on an exception. `tool` is `None` for a provider-phase
  failure (the exception happened before any call was obtained), so it is
  rendered defensively rather than assumed to always be a string.
- `failed_findings` are `record_finding` attempts that failed validation.
  Without surfacing at least a count, a model that fails twice and moves on
  under-reports silently - the analyst would never know it tried.
"""

import json as json_lib
import sys

import click

# Confidence -> color, reusing the severity palette utils.print_finding uses
# (high=red, medium=yellow, low=blue) so a finding's confidence reads with
# the same visual weight as every other severity in this codebase.
_CONFIDENCE_COLOR_NAMES = {"high": "RED", "medium": "YELLOW", "low": "BLUE"}


@click.group()
def agent():
    """Agents that orchestrate BSOT commands."""
    pass


@agent.command('list')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def list_agents(json_output):
    """
    List the available agents.

    \b
    Examples:
        bsot agent list
    """
    from .definitions import get_definition, list_definitions
    from ..utils import Colors, print_header

    names = list_definitions()

    if json_output:
        click.echo(json_lib.dumps({
            'agents': [
                {
                    'name': n,
                    'effort': get_definition(n).effort,
                    'max_iterations': get_definition(n).max_iterations,
                }
                for n in names
            ]
        }, indent=2))
        return

    print_header('Available Agents')
    for name in names:
        definition = get_definition(name)
        click.echo(
            f"  {Colors.CYAN}{name:12s}{Colors.RESET} "
            f"effort={definition.effort} max_iterations={definition.max_iterations}"
        )
    click.echo()


# The contract version for the exported catalogue, consumed by external
# programs (sec-team-mcp). Bump ONLY on a breaking reshape of an entry:
# removing a key, changing a key's type, or changing the meaning of `tier`.
# Adding a new key is backward-compatible and does not bump it. This is
# deliberately independent of the bsot package version, which moves for
# unrelated reasons and so cannot serve as a break signal.
CATALOGUE_VERSION = 1


@agent.command()
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def catalogue(json_output):
    """
    Export every agent-callable command as a tool schema.

    Publishes what bridge.py derives from the Click tree plus the safety
    tier safety.py assigns, so an external orchestrator can build its own
    tool definitions without importing bsot. The `agent` group is absent by
    construction (bridge.build_catalogue skips it).

    \b
    Examples:
        bsot agent catalogue --json
    """
    from .bridge import build_catalogue
    from .safety import tier_for
    from .. import __version__

    commands = []
    for tool in build_catalogue():
        path = tool["_command_path"]
        commands.append({
            'name': tool['name'],
            'path': list(path),
            'description': tool['description'],
            'input_schema': tool['input_schema'],
            'params': tool['_params'],
            'supports_json': tool['_supports_json'],
            'tier': tier_for(path).value,
        })

    if json_output:
        click.echo(json_lib.dumps({
            'bsot_version': __version__,
            'catalogue_version': CATALOGUE_VERSION,
            'commands': commands,
        }, indent=2))
        return

    from ..utils import Colors, print_header

    print_header(f"Agent catalogue ({len(commands)} commands)")
    by_tier = {}
    for entry in commands:
        by_tier.setdefault(entry['tier'], []).append(entry['name'])
    for tier in sorted(by_tier):
        click.echo(f"{Colors.BOLD}{tier}{Colors.RESET} "
                   f"({len(by_tier[tier])})")
        for name in sorted(by_tier[tier]):
            click.echo(f"  {name}")


def _render_status(run_obj, Colors, print_header, print_subheader):
    """
    Human-readable summary of one run.

    stop_reason drives the headline: "max_iterations" and "error" each get a
    visually distinct, impossible-to-miss banner so a truncated or crashed
    run can never be mistaken for a clean "completed" one at a glance.
    """
    print_header(f"Agent run: {run_obj.run_id}")
    click.echo(f"  Tool calls: {len(run_obj.transcript)}")

    if run_obj.stop_reason == "max_iterations":
        click.echo(
            f"  {Colors.YELLOW}{Colors.BOLD}⚠ TRUNCATED{Colors.RESET}"
            f"{Colors.YELLOW} - hit the max-iterations cap "
            f"({run_obj.max_iterations}) while the agent still had more to "
            f"do. This investigation is INCOMPLETE; findings below are "
            f"partial.{Colors.RESET}"
        )
    elif run_obj.stop_reason == "refusal":
        click.echo(
            f"  {Colors.RED}{Colors.BOLD}✗ DECLINED{Colors.RESET}"
            f"{Colors.RED} - the model's safety classifiers declined this "
            f"request, so the artifact was NEVER ANALYZED. This is not a "
            f"clean verdict. Investigate by hand, or with the individual "
            f"bsot commands.{Colors.RESET}"
        )
    elif run_obj.stop_reason == "max_tokens":
        click.echo(
            f"  {Colors.YELLOW}{Colors.BOLD}⚠ TRUNCATED{Colors.RESET}"
            f"{Colors.YELLOW} - the model hit its token ceiling mid-response. "
            f"This investigation is INCOMPLETE; findings below are partial."
            f"{Colors.RESET}"
        )
    elif run_obj.stop_reason == "error":
        click.echo(f"  {Colors.RED}{Colors.BOLD}✗ ERROR{Colors.RESET}")
        err = run_obj.error or {}
        tool = err.get('tool') or '(none - failed before any tool call)'
        click.echo(f"  {Colors.RED}Phase:{Colors.RESET} {err.get('phase', 'unknown')}")
        click.echo(f"  {Colors.RED}Tool:{Colors.RESET} {tool}")
        click.echo(
            f"  {Colors.RED}{err.get('exception_type', 'Exception')}:{Colors.RESET} "
            f"{err.get('message', '')}"
        )
        click.echo(
            f"  {Colors.DIM}The run ended early; results below reflect only "
            f"what was recorded before the failure.{Colors.RESET}"
        )
    else:
        click.echo(f"  {Colors.GREEN}Status: completed{Colors.RESET}")

    if run_obj.failed_findings:
        click.echo(
            f"  {Colors.YELLOW}{len(run_obj.failed_findings)} finding attempt(s) "
            f"failed validation and were NOT recorded (see below).{Colors.RESET}"
        )

    if len(run_obj.findings):
        counts = run_obj.findings.counts_by_confidence()
        counts_str = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print_subheader(f"Findings ({len(run_obj.findings)}: {counts_str})")
        for finding in run_obj.findings:
            color = getattr(Colors, _CONFIDENCE_COLOR_NAMES.get(finding.confidence, 'RESET'))
            click.echo(f"  • {color}[{finding.confidence}]{Colors.RESET} {finding.claim}")
            click.echo(f"    {Colors.DIM}{finding.source_command} (exit {finding.exit_code}){Colors.RESET}")
            if finding.evidence:
                click.echo(f"    {Colors.DIM}evidence: {finding.evidence}{Colors.RESET}")

    if run_obj.failed_findings:
        print_subheader(f"Failed finding attempts ({len(run_obj.failed_findings)})")
        for failed in run_obj.failed_findings:
            claim = failed.get('params', {}).get('claim', '(no claim)')
            click.echo(f"  {Colors.YELLOW}• {claim}{Colors.RESET}")
            click.echo(f"    {Colors.DIM}{failed.get('error')}{Colors.RESET}")

    if run_obj.pending_approval:
        print_subheader(f"Awaiting human approval ({len(run_obj.pending_approval)})")
        for entry in run_obj.pending_approval:
            command_name = "bsot " + " ".join(entry.get('command_path', []))
            click.echo(f"  {Colors.YELLOW}{entry['tool']}{Colors.RESET} ({command_name})")
            click.echo(f"    {Colors.DIM}params: {entry.get('params')}{Colors.RESET}")

    click.echo()


@agent.command()
@click.argument('name')
@click.option('--task', required=True, help='What the agent should investigate')
@click.option('--max-iterations', type=int, help='Cap on tool-calling turns')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def run(name, task, max_iterations, json_output):
    """
    Run an agent against a task.

    \b
    Exit codes:
      0 - Completed with no findings and nothing awaiting approval
      1 - Findings were recorded, or a tool call is awaiting human approval
      2 - Unknown agent, missing API key, or the run itself ended in error

    \b
    Examples:
        bsot agent run triage --task "investigate suspicious.eml"
    """
    from .definitions import get_definition, list_definitions
    from .runtime import AgentRun, AnthropicProvider
    from ..utils import Colors, print_header, print_subheader

    # Checked via list_definitions() rather than catching get_definition's
    # KeyError directly: str(KeyError(msg)) is repr(msg), not msg itself, so
    # printing the caught exception verbatim wraps the whole message in an
    # extra, confusing pair of quotes (KeyError's __str__ contract, not a bug
    # in .definitions). This keeps the error line plain, matching every other
    # "Error: unknown X" message in this codebase (e.g. bsot/cli.py's
    # config_check unknown-service error).
    if name not in list_definitions():
        click.echo(f"Error: unknown agent '{name}'.", err=True)
        click.echo(f"Known: {', '.join(list_definitions())}", err=True)
        sys.exit(2)
    definition = get_definition(name)

    try:
        provider = AnthropicProvider(effort=definition.effort)
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    run_obj = AgentRun(agent=name, provider=provider, max_iterations=max_iterations)
    run_obj.execute(task)

    if json_output:
        click.echo(json_lib.dumps({
            'run_id': run_obj.run_id,
            'agent': name,
            'stop_reason': run_obj.stop_reason,
            'error': run_obj.error,
            'max_iterations': run_obj.max_iterations,
            'findings': run_obj.findings.to_dict(),
            'failed_findings': run_obj.failed_findings,
            'pending_approval': run_obj.pending_approval,
            'transcript': run_obj.transcript,
        }, indent=2, default=str))
    else:
        _render_status(run_obj, Colors, print_header, print_subheader)

    # Exit code precedence, deliberately in this order:
    #   1. stop_reason == "error" -> 2. A run that crashed did not "find"
    #      anything - reporting it as 1 (findings) would let a failed run
    #      pass for a successful triage even if some findings were recorded
    #      before the crash, which is the one scenario this ordering exists
    #      to prevent.
    #   2. findings recorded, or a call is awaiting approval -> 1, matching
    #      this codebase's convention (0 clean, 1 findings, 2 error).
    #   3. otherwise -> 0.
    #   1b. stop_reason == "refusal" -> 2 as well. The artifact was never
    #      analyzed, so exiting 0 would report "declined" as "clean" - the
    #      one outcome this whole design exists to make impossible.
    if run_obj.stop_reason in ("error", "refusal"):
        sys.exit(2)
    if len(run_obj.findings) or run_obj.pending_approval:
        sys.exit(1)
    # An incomplete run with nothing to show is not a clean bill of health:
    # exit 1 rather than 0 so a truncated investigation can't be scripted
    # against as a pass.
    if run_obj.stop_reason in ("max_iterations", "max_tokens"):
        sys.exit(1)
