#!/usr/bin/env python3
"""Base64 decode command"""

import click
import base64
import binascii
import re

@click.command('base64-decode')
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
