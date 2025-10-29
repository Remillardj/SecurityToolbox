#!/usr/bin/env python3
"""Hex decode command"""

import click

@click.command('hex-decode')
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
