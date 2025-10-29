#!/usr/bin/env python3
"""
BSOT - Blue Security Ops Toolkit
A comprehensive CLI tool for security operations and analysis.
"""

import click

# Lazy import wrapper for command groups
class LazyGroup(click.Group):
    def __init__(self, *args, lazy_subcommands=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.lazy_subcommands = lazy_subcommands or {}

    def get_command(self, ctx, cmd_name):
        # Check if already loaded
        if cmd_name in self.commands:
            return self.commands[cmd_name]

        # Lazy load if configured
        if cmd_name in self.lazy_subcommands:
            module_name, attr_name = self.lazy_subcommands[cmd_name]
            module = __import__(module_name, fromlist=[attr_name])
            command = getattr(module, attr_name)
            self.add_command(command, cmd_name)
            return command

        return None

    def list_commands(self, ctx):
        # Return all available commands (both loaded and lazy)
        return sorted(set(self.commands.keys()) | set(self.lazy_subcommands.keys()))

@click.command(cls=LazyGroup, lazy_subcommands={
    'file': ('commands.file', 'file_group'),
    'network': ('commands.network', 'network_group'),
    'data': ('commands.data_commands', 'data_group'),
    'auth': ('commands.auth', 'auth_group'),
    'system': ('commands.system', 'system_group'),
    'logs': ('commands.logs', 'logs_group'),
})
@click.version_option(version='1.0.0')
def cli():
    """BSOT - Blue Security Ops Toolkit

    A comprehensive security toolkit for file analysis, network scanning,
    data decoding, authentication auditing, system monitoring, and log analysis.
    """
    pass

if __name__ == '__main__':
    cli()
