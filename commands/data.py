#!/usr/bin/env python3
"""
Data encoding/decoding and analysis commands
"""

import click
import base64
import binascii
from urllib.parse import unquote, unquote_plus
import json
import re

@click.group('data')
def data_group():
    """Data encoding/decoding and analysis tools"""
    pass

@data_group.command('url-decode')
@click.argument('encoded_string')
@click.option('-p', '--plus', is_flag=True, help='Treat + as spaces (application/x-www-form-urlencoded)')
@click.option('-r', '--recursive', is_flag=True, help='Decode recursively until no more encoding detected')
def url_decode(encoded_string, plus, recursive):
    """Decode URL-encoded strings

    Examples:
        bsot data url-decode "Hello%20World"
        bsot data url-decode "name%3Dvalue%26foo%3Dbar" --recursive
    """
    result = encoded_string
    decode_count = 0

    while True:
        try:
            if plus:
                decoded = unquote_plus(result)
            else:
                decoded = unquote(result)

            decode_count += 1
            result = decoded

            if decoded == result or not recursive:
                # No more decoding possible or recursive mode disabled
                break
        except Exception as e:
            click.echo(f"Error during decoding: {e}", err=True)
            break

    if recursive and decode_count > 1:
        click.echo(f"Decoded {decode_count} times:")

    click.echo(result)

@data_group.command('base64-decode')
@click.argument('encoded_string', required=False)
@click.option('-f', '--file', type=click.Path(exists=True), help='Decode from file')
@click.option('-r', '--recursive', is_flag=True, help='Decode recursively until no more encoding detected')
@click.option('-u', '--url-safe', is_flag=True, help='Use URL-safe base64 decoding')
def base64_decode(encoded_string, file, recursive, url_safe):
    """Decode base64-encoded strings

    Examples:
        bsot data base64-decode "SGVsbG8gV29ybGQ="
        bsot data base64-decode --file encoded.txt
        bsot data base64-decode "U0dWc2JHOGdWMjl5YkdRPQ==" --recursive
    """
    if file:
        with open(file, 'r') as f:
            encoded_string = f.read().strip()

    if not encoded_string:
        click.echo("Error: No input provided", err=True)
        return

    result = encoded_string
    decode_count = 0

    while True:
        try:
            # Clean up the input (remove whitespace/newlines)
            cleaned = result.strip().replace('\n', '').replace('\r', '')

            if url_safe:
                decoded_bytes = base64.urlsafe_b64decode(cleaned)
            else:
                decoded_bytes = base64.b64decode(cleaned)

            decode_count += 1

            # Try to decode as UTF-8
            try:
                decoded = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # If not UTF-8, show hex representation
                click.echo(f"Binary data (hex): {decoded_bytes.hex()}")
                break

            # Check if result looks like base64 (for recursive mode)
            is_base64 = bool(re.match(r'^[A-Za-z0-9+/=\-_]+$', decoded.strip()))

            if not is_base64 or not recursive or decoded == result:
                # No more decoding possible
                result = decoded
                break

            result = decoded
        except (binascii.Error, ValueError) as e:
            if decode_count == 1:
                click.echo(f"Error: Invalid base64 input - {e}", err=True)
            break

    if recursive and decode_count > 1:
        click.echo(f"Decoded {decode_count} times:")

    click.echo(result)

@data_group.command('hex-decode')
@click.argument('hex_string', required=False)
@click.option('-f', '--file', type=click.Path(exists=True), help='Decode from file')
@click.option('-p', '--prefix', is_flag=True, help='Expect 0x prefix on each byte')
def hex_decode(hex_string, file, prefix):
    """Decode hexadecimal strings

    Examples:
        bsot data hex-decode "48656c6c6f20576f726c64"
        bsot data hex-decode "0x480x650x6c0x6c0x6f" --prefix
        bsot data hex-decode --file encoded.txt
    """
    if file:
        with open(file, 'r') as f:
            hex_string = f.read().strip()

    if not hex_string:
        click.echo("Error: No input provided", err=True)
        return

    try:
        # Clean the input
        cleaned = hex_string.strip().replace(' ', '').replace('\n', '').replace('\r', '')

        if prefix:
            # Remove 0x prefixes
            cleaned = cleaned.replace('0x', '').replace('0X', '')

        # Decode hex to bytes
        decoded_bytes = bytes.fromhex(cleaned)

        # Try to decode as UTF-8
        try:
            result = decoded_bytes.decode('utf-8')
            click.echo(result)
        except UnicodeDecodeError:
            # If not UTF-8, show both hex and raw bytes info
            click.echo(f"Binary data ({len(decoded_bytes)} bytes):")
            click.echo(f"Hex: {decoded_bytes.hex()}")
            click.echo(f"Printable: {repr(decoded_bytes)}")
    except ValueError as e:
        click.echo(f"Error: Invalid hexadecimal input - {e}", err=True)

@data_group.command('email-header')
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
    from email.parser import Parser
    from email.utils import parseaddr
    import datetime

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
