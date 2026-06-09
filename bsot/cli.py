"""
BSOT - Blue Security Ops Toolkit
Main CLI entry point with plugin auto-discovery.
"""

import click
import importlib
from typing import List, Tuple

from . import __version__


class LazyGroup(click.Group):
    """Lazy-loading command group for faster startup."""
    
    def __init__(self, name, import_name, **attrs):
        super().__init__(name=name, **attrs)
        self._import_name = import_name
        self._impl = None
    
    def _load(self):
        if self._impl is None:
            module = importlib.import_module(self._import_name)
            self._impl = getattr(module, self.name)
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
        ('phishing', 'bsot.phishing.cli'),
        ('intel', 'bsot.intel.cli'),
        ('file', 'bsot.file.cli'),
        ('network', 'bsot.network.cli'),
        ('logs', 'bsot.logs.cli'),
        ('data', 'bsot.data.cli'),
        ('auth', 'bsot.auth.cli'),
        ('system', 'bsot.system.cli'),
        ('ir', 'bsot.ir.cli'),
        ('malware', 'bsot.malware.cli'),
    ]
    
    plugins = []
    for name, import_path in modules:
        lazy = LazyGroup(name, import_path, help=f"{name.title()} module")
        plugins.append((name, lazy))
    
    return plugins


@click.group()
@click.version_option(version=__version__, prog_name='bsot')
@click.option('--profile', '-p', envvar='BSOT_PROFILE', 
              help='Configuration profile to use')
@click.option('--no-cache', is_flag=True, help='Disable caching for API calls')
@click.pass_context
def cli(ctx, profile, no_cache):
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
    
    # Load config with profile if specified
    if profile:
        from .config import Config
        ctx.obj['config'] = Config(profile=profile)


# Register lazy-loading plugins (fast startup)
for name, group in get_lazy_plugins():
    cli.add_command(group, name=name)


# Manually register report module commands (case + report)
# The report module has both 'case' and 'report' command groups
try:
    from .report.cli import case as case_group, report as report_group
    cli.add_command(case_group, name='case')
    cli.add_command(report_group, name='report')
except ImportError:
    pass  # Module not installed


# Manually register OSINT module
try:
    from .osint.cli import osint as osint_group
    cli.add_command(osint_group, name='osint')
except ImportError:
    pass  # Module not installed


# Fallback: Register placeholder groups for modules not yet implemented
# These will be overwritten by actual implementations when they exist
_placeholder_modules = ['file', 'network', 'data', 'auth', 'system', 'logs', 'intel', 'malware', 'ir', 'report', 'case', 'osint']

for module_name in _placeholder_modules:
    # Check if already registered via auto-discovery
    if module_name not in [cmd.name for cmd in cli.commands.values()]:
        # Create placeholder
        @cli.group(name=module_name)
        def _placeholder():
            """Module not yet implemented."""
            pass


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
    
    click.echo(f"\n📋 BSOT Configuration")
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
    click.echo(f"\n📊 Cache Statistics")
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
