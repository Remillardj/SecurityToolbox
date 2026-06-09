"""
Encoding/Decoding Utilities
Support for various encoding formats.
"""

import base64
import codecs
import html
import urllib.parse
from typing import Optional


ENCODINGS = ['base64', 'url', 'hex', 'html', 'unicode-escape', 'rot13', 'punycode']


def decode(data: str, encoding: str) -> str:
    """
    Decode data using specified encoding.
    
    Args:
        data: Data to decode
        encoding: Encoding type
        
    Returns:
        Decoded string
        
    Raises:
        ValueError: If decoding fails
    """
    encoding = encoding.lower()
    
    if encoding == 'base64':
        return decode_base64(data)
    elif encoding == 'url':
        return decode_url(data)
    elif encoding == 'hex':
        return decode_hex(data)
    elif encoding == 'html':
        return decode_html(data)
    elif encoding == 'unicode-escape' or encoding == 'unicode':
        return decode_unicode_escape(data)
    elif encoding == 'rot13':
        return decode_rot13(data)
    elif encoding == 'punycode':
        return decode_punycode(data)
    else:
        raise ValueError(f"Unknown encoding: {encoding}")


def encode(data: str, encoding: str) -> str:
    """
    Encode data using specified encoding.
    
    Args:
        data: Data to encode
        encoding: Encoding type
        
    Returns:
        Encoded string
    """
    encoding = encoding.lower()
    
    if encoding == 'base64':
        return encode_base64(data)
    elif encoding == 'url':
        return encode_url(data)
    elif encoding == 'hex':
        return encode_hex(data)
    elif encoding == 'html':
        return encode_html(data)
    elif encoding == 'unicode-escape' or encoding == 'unicode':
        return encode_unicode_escape(data)
    elif encoding == 'rot13':
        return encode_rot13(data)
    elif encoding == 'punycode':
        return encode_punycode(data)
    else:
        raise ValueError(f"Unknown encoding: {encoding}")


def decode_chain(data: str, encodings: list) -> str:
    """
    Decode data through a chain of encodings.
    
    Args:
        data: Data to decode
        encodings: List of encodings to apply in order
        
    Returns:
        Decoded string
    """
    result = data
    for enc in encodings:
        result = decode(result, enc)
    return result


# Base64
def decode_base64(data: str) -> str:
    """Decode base64."""
    # Handle URL-safe base64
    data = data.replace('-', '+').replace('_', '/')
    
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    
    try:
        decoded = base64.b64decode(data)
        return decoded.decode('utf-8', errors='replace')
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")


def encode_base64(data: str) -> str:
    """Encode to base64."""
    return base64.b64encode(data.encode()).decode()


# URL encoding
def decode_url(data: str) -> str:
    """Decode URL-encoded string."""
    return urllib.parse.unquote(data)


def encode_url(data: str) -> str:
    """URL-encode a string."""
    return urllib.parse.quote(data, safe='')


# Hex
def decode_hex(data: str) -> str:
    """Decode hex string."""
    # Remove common prefixes and separators
    data = data.replace('0x', '').replace('\\x', '').replace(' ', '').replace(':', '')
    
    try:
        decoded = bytes.fromhex(data)
        return decoded.decode('utf-8', errors='replace')
    except Exception as e:
        raise ValueError(f"Hex decode failed: {e}")


def encode_hex(data: str) -> str:
    """Encode to hex."""
    return data.encode().hex()


# HTML entities
def decode_html(data: str) -> str:
    """Decode HTML entities."""
    return html.unescape(data)


def encode_html(data: str) -> str:
    """Encode HTML entities."""
    return html.escape(data)


# Unicode escape sequences
def decode_unicode_escape(data: str) -> str:
    """Decode Unicode escape sequences (\\uXXXX)."""
    try:
        return codecs.decode(data, 'unicode_escape')
    except Exception:
        # Try raw_unicode_escape for different format
        try:
            return codecs.decode(data, 'raw_unicode_escape')
        except Exception as e:
            raise ValueError(f"Unicode decode failed: {e}")


def encode_unicode_escape(data: str) -> str:
    """Encode to Unicode escape sequences."""
    return data.encode('unicode_escape').decode('ascii')


# ROT13
def decode_rot13(data: str) -> str:
    """Decode ROT13."""
    return codecs.decode(data, 'rot_13')


def encode_rot13(data: str) -> str:
    """Encode ROT13 (same as decode)."""
    return codecs.encode(data, 'rot_13')


# Punycode (for internationalized domain names)
def decode_punycode(data: str) -> str:
    """Decode Punycode domain."""
    if data.startswith('xn--'):
        try:
            return data.encode().decode('idna')
        except Exception:
            pass
    
    # Handle full domain with multiple parts
    parts = data.split('.')
    decoded_parts = []
    for part in parts:
        if part.startswith('xn--'):
            try:
                decoded_parts.append(part.encode().decode('idna'))
            except Exception:
                decoded_parts.append(part)
        else:
            decoded_parts.append(part)
    
    return '.'.join(decoded_parts)


def encode_punycode(data: str) -> str:
    """Encode to Punycode."""
    try:
        return data.encode('idna').decode('ascii')
    except Exception as e:
        raise ValueError(f"Punycode encode failed: {e}")


# Detection
def detect_encoding(data: str) -> Optional[str]:
    """
    Try to detect the encoding of data.
    
    Returns:
        Detected encoding name or None
    """
    # Check for base64 pattern
    if len(data) > 4 and len(data) % 4 == 0:
        import re
        if re.match(r'^[A-Za-z0-9+/=]+$', data):
            try:
                decode_base64(data)
                return 'base64'
            except ValueError:
                pass
    
    # Check for URL encoding
    if '%' in data:
        return 'url'
    
    # Check for hex
    if data.startswith('0x') or data.startswith('\\x'):
        return 'hex'
    if len(data) > 2 and all(c in '0123456789abcdefABCDEF' for c in data):
        if len(data) % 2 == 0:
            return 'hex'
    
    # Check for HTML entities
    if '&' in data and ';' in data:
        return 'html'
    
    # Check for unicode escapes
    if '\\u' in data:
        return 'unicode-escape'
    
    # Check for punycode
    if 'xn--' in data:
        return 'punycode'
    
    return None

