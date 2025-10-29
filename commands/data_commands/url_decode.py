#!/usr/bin/env python3
"""URL decode command"""

import click
from urllib.parse import unquote, unquote_plus

@click.command('url-decode')
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
