"""Data encoding/decoding commands"""

import click
from .url_decode import url_decode
from .base64_decode import base64_decode
from .hex_decode import hex_decode
from .email_header import email_header

@click.group('data')
def data_group():
    """Data encoding/decoding and analysis tools"""
    pass

# Register commands
data_group.add_command(url_decode)
data_group.add_command(base64_decode)
data_group.add_command(hex_decode)
data_group.add_command(email_header)
