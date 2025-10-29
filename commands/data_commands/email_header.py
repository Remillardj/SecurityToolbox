#!/usr/bin/env python3
"""Email header analysis command"""

import click
import json
from email.parser import Parser
from email.utils import parseaddr

@click.command('email-header')
@click.argument('header_file', type=click.Path(exists=True))
@click.option('-v', '--verbose', is_flag=True, help='Show detailed analysis')
@click.option('-j', '--json', 'output_json', is_flag=True, help='Output as JSON')
def email_header(header_file, verbose, output_json):
    """Analyze email headers for security issues

    Examples:
        bsot data email-header headers.txt
        bsot data email-header headers.txt --verbose
        bsot data email-header headers.txt --json
    """
    with open(header_file, 'r') as f:
        headers = Parser().parse(f)

    # Extract key information
    analysis = {
        'from': headers.get('From'),
        'to': headers.get('To'),
        'subject': headers.get('Subject'),
        'date': headers.get('Date'),
        'message_id': headers.get('Message-ID'),
        'return_path': headers.get('Return-Path'),
        'received_hops': [],
        'authentication': {},
        'warnings': [],
        'security_headers': {}
    }

    # Parse authentication results
    spf = headers.get('Received-SPF')
    dkim = headers.get('DKIM-Signature')
    dmarc = headers.get('Authentication-Results')

    if spf:
        analysis['authentication']['SPF'] = spf
        if 'pass' not in spf.lower():
            analysis['warnings'].append('SPF check did not pass')

    if dkim:
        analysis['authentication']['DKIM'] = 'Present'
    else:
        analysis['warnings'].append('No DKIM signature found')

    if dmarc:
        analysis['authentication']['DMARC'] = dmarc

    # Parse received headers (trace route)
    for header in headers.get_all('Received', []):
        analysis['received_hops'].append(header.strip())

    # Check for spoofing indicators
    from_addr = parseaddr(headers.get('From', ''))[1]
    return_path = parseaddr(headers.get('Return-Path', ''))[1]

    if from_addr and return_path and from_addr.lower() != return_path.lower():
        analysis['warnings'].append(f'From address ({from_addr}) differs from Return-Path ({return_path}) - possible spoofing')

    # Check for suspicious reply-to
    reply_to = headers.get('Reply-To')
    if reply_to:
        reply_addr = parseaddr(reply_to)[1]
        if from_addr and reply_addr.lower() != from_addr.lower():
            analysis['warnings'].append(f'Reply-To address ({reply_addr}) differs from From address - possible phishing')

    # Output results
    if output_json:
        click.echo(json.dumps(analysis, indent=2))
    else:
        click.echo("=" * 60)
        click.echo("EMAIL HEADER ANALYSIS")
        click.echo("=" * 60)
        click.echo(f"\nFrom: {analysis['from']}")
        click.echo(f"To: {analysis['to']}")
        click.echo(f"Subject: {analysis['subject']}")
        click.echo(f"Date: {analysis['date']}")

        if analysis['authentication']:
            click.echo(f"\nAUTHENTICATION:")
            for key, value in analysis['authentication'].items():
                click.echo(f"  {key}: {value}")

        if analysis['warnings']:
            click.echo(f"\n⚠️  SECURITY WARNINGS:")
            for warning in analysis['warnings']:
                click.echo(f"  - {warning}")

        if verbose and analysis['received_hops']:
            click.echo(f"\nEMAIL ROUTE ({len(analysis['received_hops'])} hops):")
            for i, hop in enumerate(analysis['received_hops'], 1):
                click.echo(f"  {i}. {hop[:80]}...")
