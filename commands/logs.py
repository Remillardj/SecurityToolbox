#!/usr/bin/env python3
"""
Log analysis commands
"""

import click
import json
from pathlib import Path
from commands.utils.log_analyzer import LogPatternAnalyzer

@click.group('logs')
def logs_group():
    """Log analysis and security monitoring tools"""
    pass

@logs_group.command('analyze')
@click.argument('log_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Choice(['text', 'json'], case_sensitive=False),
              default='text', help='Output format')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('-p', '--patterns', type=click.Path(exists=True),
              help='JSON file containing custom patterns to search for')
@click.option('-f', '--focus', help='Focus on specific information: ip, brute_force, username, compromised, email, url')
@click.option('-q', '--query', help='Ask a specific question (e.g., "What is the username of the compromised account?")')
def analyze(log_file, output, verbose, patterns, focus, query):
    """Analyze log files for patterns and security indicators

    Examples:
        bsot logs analyze /var/log/auth.log
        bsot logs analyze access.log --focus ip
        bsot logs analyze auth.log --query "What is the compromised account?"
        bsot logs analyze app.log --patterns custom_patterns.json --output json
    """
    if not Path(log_file).exists():
        click.echo(f"Error: Log file '{log_file}' does not exist.", err=True)
        return

    # Load custom patterns if provided
    custom_patterns = None
    if patterns:
        if not Path(patterns).exists():
            click.echo(f"Error: Pattern file '{patterns}' does not exist.", err=True)
            return

        try:
            with open(patterns, 'r') as f:
                custom_patterns = json.load(f)
            if verbose:
                click.echo(f"Loaded {len(custom_patterns)} custom patterns from {patterns}")
        except json.JSONDecodeError as e:
            click.echo(f"Error: Invalid JSON in pattern file: {e}", err=True)
            return
        except Exception as e:
            click.echo(f"Error reading pattern file: {e}", err=True)
            return

    analyzer = LogPatternAnalyzer(custom_patterns)

    if verbose:
        click.echo(f"Analyzing log file: {log_file}")
        if custom_patterns:
            click.echo(f"Custom patterns loaded: {list(custom_patterns.keys())}")

    if analyzer.analyze_file(log_file):
        analyzer.analyze_attack_scenarios()
        analyzer.detect_suspicious_logins()
        analyzer.generate_statistics()
        analyzer.print_results(output, focus=focus, query=query)
    else:
        click.echo("Failed to analyze log file", err=True)
