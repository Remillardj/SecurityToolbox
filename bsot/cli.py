"""
BSOT - Blue Security Ops Toolkit
Main CLI entry point with plugin auto-discovery.
"""

import click
import importlib
import json as json_lib
import sys
from typing import List, Tuple

from . import __version__


class LazyGroup(click.Group):
    """Lazy-loading command group for faster startup."""

    def __init__(self, name, import_name, attr=None, **attrs):
        super().__init__(name=name, **attrs)
        self._import_name = import_name
        self._attr = attr or name
        self._impl = None

    def _load(self):
        if self._impl is None:
            try:
                module = importlib.import_module(self._import_name)
            except ImportError as e:
                # Name the missing dependency instead of letting the module look
                # unimplemented — an optional extra is the usual cause.
                raise click.ClickException(
                    f"The '{self.name}' module could not be loaded: {e}\n"
                    f"It may need an optional dependency. Try: "
                    f"pip install 'bsot[full]'  (or [malware] / [report])"
                ) from e
            self._impl = getattr(module, self._attr)
        return self._impl

    def get_command(self, ctx, cmd_name):
        return self._load().get_command(ctx, cmd_name)

    def list_commands(self, ctx):
        return self._load().list_commands(ctx)

    def invoke(self, ctx):
        return self._load().invoke(ctx)


def get_lazy_plugins() -> List[Tuple[str, LazyGroup]]:
    """
    Return lazy-loading command groups for faster startup.
    Modules only load when actually invoked.
    """
    modules = [
        ('phishing', 'bsot.phishing.cli', 'phishing', 'Phishing email analysis tools'),
        ('intel', 'bsot.intel.cli', 'intel', 'Threat intelligence lookups'),
        ('file', 'bsot.file.cli', 'file', 'File analysis and forensics'),
        ('network', 'bsot.network.cli', 'network', 'Network security tools'),
        ('logs', 'bsot.logs.cli', 'logs', 'Log analysis utilities'),
        ('data', 'bsot.data.cli', 'data', 'Data encoding/decoding utilities'),
        ('auth', 'bsot.auth.cli', 'auth', 'Authentication analysis'),
        ('system', 'bsot.system.cli', 'system', 'System monitoring tools'),
        ('ir', 'bsot.ir.cli', 'ir', 'Incident response tools'),
        ('malware', 'bsot.malware.cli', 'malware', 'Malware static analysis tools'),
        # The report module exposes two groups from one module.
        ('case', 'bsot.report.cli', 'case', 'Investigation case management'),
        ('report', 'bsot.report.cli', 'report', 'Report generation and export'),
        ('osint', 'bsot.osint.cli', 'osint', 'Open Source Intelligence tools'),
        ('agent', 'bsot.agent.cli', 'agent', 'Agents that orchestrate BSOT commands'),
    ]

    plugins = []
    for name, import_path, attr, help_text in modules:
        lazy = LazyGroup(name, import_path, attr=attr, help=help_text)
        plugins.append((name, lazy))

    return plugins


@click.group()
@click.version_option(version=__version__, prog_name='bsot')
@click.option('--profile', '-p', envvar='BSOT_PROFILE', 
              help='Configuration profile to use')
@click.option('--no-cache', is_flag=True, help='Disable caching for API calls')
@click.option('--defang/--no-defang', default=True, show_default=True,
              help='Defang indicators in human-readable output')
@click.pass_context
def cli(ctx, profile, no_cache, defang):
    """
    BSOT - Blue Security Ops Toolkit
    
    A comprehensive security toolkit for blue team operations.
    
    \b
    Available command groups:
      phishing    Phishing email analysis tools
      intel       Threat intelligence lookups
      file        File analysis and forensics
      network     Network security tools
      logs        Log analysis utilities
      data        Data encoding/decoding utilities
      auth        Authentication analysis
      system      System monitoring tools
      ir          Incident response tools
      malware     Malware static analysis tools
      case        Investigation case management
      report      Report generation and export
      osint       Open Source Intelligence tools
      agent       Agents that orchestrate BSOT commands

    \b
    Example usage:
      bsot phishing analyze suspicious.eml
      bsot intel enrich 1.2.3.4
      bsot file hash malware.exe
      bsot logs analyze -f auth.log
    
    \b
    Configuration:
      API keys can be set via environment variables or ~/.bsot/config.json
      Use --profile to switch between named configurations
    
    For more information on a command, run:
      bsot <command> --help
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    ctx.obj['profile'] = profile
    ctx.obj['no_cache'] = no_cache
    ctx.obj['defang'] = defang

    # Human-readable output defaults to defanged so results are safe to paste
    # into tickets and chat. JSON output is unaffected.
    from .utils import set_defang
    set_defang(defang)
    
    # Load config with profile if specified
    if profile:
        from .config import Config
        ctx.obj['config'] = Config(profile=profile)


# Register lazy-loading plugins (fast startup)
for name, group in get_lazy_plugins():
    cli.add_command(group, name=name)


# Config management commands
@cli.group()
def config():
    """Manage BSOT configuration and API keys."""
    pass


@config.command('show')
@click.option('--profile', '-p', help='Profile to show')
@click.option('--show-keys', is_flag=True, help='Show API key values (masked)')
def config_show(profile, show_keys):
    """Show current configuration."""
    from .config import get_config
    
    cfg = get_config(profile)
    
    click.echo("\n📋 BSOT Configuration")
    if profile:
        click.echo(f"   Profile: {profile}")
    click.echo()
    
    # Show API key status
    click.echo("🔑 API Keys:")
    for key_name in ['openai', 'anthropic', 'virustotal', 'abuseipdb', 
                     'greynoise', 'otx', 'ipinfo', 'shodan', 'urlscan']:
        has_key = cfg.has_api_key(key_name)
        status = "✅ configured" if has_key else "❌ not set"
        click.echo(f"   {key_name}: {status}")
    
    click.echo()


@config.command('set')
@click.argument('key')
@click.argument('value')
@click.option('--profile', '-p', help='Profile to update')
def config_set(key, value, profile):
    """Set a configuration value."""
    from .config import get_config
    
    cfg = get_config(profile)
    cfg.set(key, value, profile)
    click.echo(f"✅ Set {key} in {'profile ' + profile if profile else 'default config'}")


@config.command('profiles')
def config_profiles():
    """List available profiles."""
    from .config import config
    
    profiles = config.list_profiles()
    click.echo("\n📂 Available Profiles:")
    for p in profiles:
        click.echo(f"   • {p}")
    click.echo()


@config.command('create-profile')
@click.argument('name')
@click.option('--copy-from', help='Copy settings from existing profile')
def config_create_profile(name, copy_from):
    """Create a new configuration profile."""
    from .config import config
    
    config.create_profile(name, copy_from)
    click.echo(f"✅ Created profile: {name}")


# Cache management commands
@cli.group()
def cache():
    """Manage BSOT cache."""
    pass


@cache.command('stats')
def cache_stats():
    """Show cache statistics."""
    from .cache import cache
    
    stats = cache.stats()
    click.echo("\n📊 Cache Statistics")
    click.echo(f"   Total entries: {stats['total_entries']}")
    click.echo(f"   Total size: {stats['total_size_bytes'] / 1024:.1f} KB")
    click.echo()
    
    if stats['services']:
        click.echo("   Per-service:")
        for service, data in stats['services'].items():
            click.echo(f"   • {service}: {data['entries']} entries ({data['size_bytes'] / 1024:.1f} KB)")
    click.echo()


@cache.command('clear')
@click.option('--service', '-s', help='Clear only specific service cache')
@click.confirmation_option(prompt='Are you sure you want to clear the cache?')
def cache_clear(service):
    """Clear cached data."""
    from .cache import cache
    
    cache.clear(service)
    if service:
        click.echo(f"✅ Cleared cache for: {service}")
    else:
        click.echo("✅ Cleared all cache")


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()


# Services BSOT can talk to, and how to prove a key works. Each probe is a
# cheap, read-only call against the provider's own account/quota endpoint.
_SERVICE_PROBES = {
    'virustotal': {
        'config_key': 'virustotal_api_key',
        'env': 'VIRUSTOTAL_API_KEY',
        'unlocks': ['intel enrich', 'system processes --vt', 'malware submit'],
        'url': 'https://www.virustotal.com/api/v3/users/{key}',
        'auth': lambda key: {'x-apikey': key},
    },
    'abuseipdb': {
        'config_key': 'abuseipdb_api_key',
        'env': 'ABUSEIPDB_API_KEY',
        'unlocks': ['intel enrich'],
        'url': 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1',
        'auth': lambda key: {'Key': key, 'Accept': 'application/json'},
    },
    'greynoise': {
        'config_key': 'greynoise_api_key',
        'env': 'GREYNOISE_API_KEY',
        'unlocks': ['intel enrich'],
        'url': 'https://api.greynoise.io/v3/community/8.8.8.8',
        'auth': lambda key: {'key': key},
    },
    'otx': {
        'config_key': 'otx_api_key',
        'env': 'OTX_API_KEY',
        'unlocks': ['intel enrich'],
        'url': 'https://otx.alienvault.com/api/v1/user/me',
        'auth': lambda key: {'X-OTX-API-KEY': key},
    },
    'ipinfo': {
        'config_key': 'ipinfo_api_key',
        'env': 'IPINFO_API_KEY',
        'unlocks': ['intel geoip'],
        'url': 'https://ipinfo.io/8.8.8.8/json?token={key}',
        'auth': lambda key: {},
    },
    'urlscan': {
        'config_key': 'urlscan_api_key',
        'env': 'URLSCAN_API_KEY',
        'unlocks': ['phishing reputation', 'phishing url'],
        'url': 'https://urlscan.io/user/quotas/',
        'auth': lambda key: {'API-Key': key},
    },
    'shodan': {
        'config_key': 'shodan_api_key',
        'env': 'SHODAN_API_KEY',
        'unlocks': ['osint'],
        'url': 'https://api.shodan.io/api-info?key={key}',
        'auth': lambda key: {},
    },
    'hybrid_analysis': {
        'config_key': 'hybrid_analysis_api_key',
        'env': 'HYBRID_ANALYSIS_API_KEY',
        'unlocks': ['malware submit'],
        'url': 'https://www.hybrid-analysis.com/api/v2/key/current',
        'auth': lambda key: {'api-key': key, 'User-Agent': 'Falcon Sandbox'},
    },
    'anthropic': {
        'config_key': 'anthropic_api_key',
        'env': 'ANTHROPIC_API_KEY',
        'unlocks': ['logs ai-analyze', 'phishing ai-analyze', 'report generate'],
        'url': 'https://api.anthropic.com/v1/models',
        'auth': lambda key: {'x-api-key': key, 'anthropic-version': '2023-06-01'},
    },
    'openai': {
        'config_key': 'openai_api_key',
        'env': 'OPENAI_API_KEY',
        'unlocks': ['logs ai-analyze', 'phishing ai-analyze', 'report generate'],
        'url': 'https://api.openai.com/v1/models',
        'auth': lambda key: {'Authorization': f'Bearer {key}'},
    },
    'cloudflare': {
        'config_key': 'cloudflare_api_token',
        'env': 'CLOUDFLARE_API_TOKEN',
        'unlocks': ['ir block', 'ir contain'],
        'url': 'https://api.cloudflare.com/client/v4/user/tokens/verify',
        'auth': lambda key: {'Authorization': f'Bearer {key}'},
    },
}


@config.command('check')
@click.option('--live', is_flag=True, help='Validate each key against the provider')
@click.option('--service', '-s', help='Check only this service')
@click.option('--profile', '-p', help='Profile to check')
@click.option('--timeout', default=10, show_default=True, help='Per-probe timeout in seconds')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def config_check(live, service, profile, timeout, json_output):
    """
    Check which API keys are configured and which commands they unlock.

    \b
    Without --live this only inspects configuration. With --live each key is
    validated against the provider using a cheap read-only call.

    \b
    Examples:
        bsot config check
        bsot config check --live
        bsot config check --live --service virustotal
    """
    import os
    from .config import get_config
    from .utils import Colors, print_header

    cfg = get_config(profile)
    probes = _SERVICE_PROBES
    if service:
        if service not in probes:
            click.echo(f"Error: unknown service '{service}'.", err=True)
            click.echo(f"Known: {', '.join(sorted(probes))}", err=True)
            sys.exit(2)
        probes = {service: probes[service]}

    results = []
    for name, spec in sorted(probes.items()):
        key = cfg.get(spec['config_key'])
        entry = {
            'service': name,
            'configured': bool(key),
            'source': 'env' if os.environ.get(spec['env']) else ('config' if key else None),
            'unlocks': spec['unlocks'],
            'valid': None,
            'detail': '',
        }

        if key and live:
            import requests
            try:
                response = requests.get(
                    spec['url'].format(key=key),
                    headers=spec['auth'](key),
                    timeout=timeout,
                )
                if response.status_code in (200, 204):
                    entry['valid'] = True
                elif response.status_code in (401, 403):
                    entry['valid'] = False
                    entry['detail'] = f'rejected (HTTP {response.status_code})'
                elif response.status_code == 429:
                    # The key authenticated; the account is just rate limited.
                    entry['valid'] = True
                    entry['detail'] = 'rate limited, but the key is accepted'
                else:
                    entry['detail'] = f'unexpected HTTP {response.status_code}'
            except requests.exceptions.Timeout:
                entry['detail'] = f'timed out after {timeout}s'
            except requests.exceptions.RequestException as e:
                entry['detail'] = f'request failed: {type(e).__name__}'

        results.append(entry)

    configured = [r for r in results if r['configured']]
    invalid = [r for r in results if r['valid'] is False]

    if json_output:
        click.echo(json_lib.dumps({
            'profile': profile,
            'checked_live': live,
            'configured_count': len(configured),
            'invalid_count': len(invalid),
            'services': results,
        }, indent=2))
    else:
        print_header('BSOT Configuration Check')
        for r in results:
            if not r['configured']:
                icon = f"{Colors.DIM}○{Colors.RESET}"
                status = f"{Colors.DIM}not configured{Colors.RESET}"
            elif r['valid'] is True:
                icon = f"{Colors.GREEN}✓{Colors.RESET}"
                status = f"{Colors.GREEN}valid{Colors.RESET}"
            elif r['valid'] is False:
                icon = f"{Colors.RED}✗{Colors.RESET}"
                status = f"{Colors.RED}{r['detail']}{Colors.RESET}"
            elif r['detail']:
                icon = f"{Colors.YELLOW}?{Colors.RESET}"
                status = f"{Colors.YELLOW}{r['detail']}{Colors.RESET}"
            else:
                icon = f"{Colors.CYAN}●{Colors.RESET}"
                status = f"set via {r['source']}"

            click.echo(f"  {icon} {r['service']:18s} {status}")
            if not r['configured']:
                click.echo(f"      {Colors.DIM}unlocks: {', '.join(r['unlocks'])}{Colors.RESET}")

        click.echo()
        click.echo(f"  {len(configured)}/{len(results)} service(s) configured.")
        if not live and configured:
            click.echo(f"  {Colors.DIM}Re-run with --live to validate the keys.{Colors.RESET}")
        click.echo()

    if invalid:
        sys.exit(1)


@cli.command()
@click.argument('shell', type=click.Choice(['bash', 'zsh', 'fish']), required=False)
def completion(shell):
    """
    Emit a shell completion script.

    \b
    Install it by sourcing the output from your shell's startup file:
        bsot completion zsh  > ~/.bsot-completion.zsh
        echo 'source ~/.bsot-completion.zsh' >> ~/.zshrc

    \b
    Or evaluate it directly:
        eval "$(bsot completion bash)"
    """
    import os

    if not shell:
        # Infer from $SHELL so the bare command still does something useful.
        shell_path = os.environ.get('SHELL', '')
        shell = os.path.basename(shell_path) if shell_path else ''
        if shell not in ('bash', 'zsh', 'fish'):
            click.echo(
                "Error: could not detect your shell; pass one explicitly "
                "(bash, zsh, or fish).",
                err=True,
            )
            sys.exit(2)

    # Click generates the script from a magic env var on the program itself.
    from click.shell_completion import get_completion_class

    completion_cls = get_completion_class(shell)
    if completion_cls is None:
        click.echo(f"Error: click does not support {shell} completion.", err=True)
        sys.exit(2)

    prog_name = 'bsot'
    complete_var = '_BSOT_COMPLETE'
    click.echo(completion_cls(cli, {}, prog_name, complete_var).source())
