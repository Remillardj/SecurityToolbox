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



def _printable_ratio(text: str) -> float:
    """
    Fraction of characters that look like real text.

    U+FFFD is excluded deliberately: decoders that use errors='replace' emit it
    for binary garbage, and str.isprintable() considers it printable — so
    counting it would score random bytes as perfectly readable.
    """
    if not text:
        return 0.0
    ok = 0
    for c in text:
        if c == '\ufffd':
            continue
        if c in '\n\r\t' or (c.isprintable() and ord(c) < 0x2500):
            ok += 1
    return ok / len(text)


def _looks_like_base64(data: str) -> bool:
    """Whether data is plausibly base64 rather than ordinary text."""
    import re
    stripped = ''.join(data.split())
    if len(stripped) < 8 or len(stripped) % 4 != 0:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', stripped):
        return False
    # Ordinary prose is also valid base64 charset; require the mixed-case and
    # digit density that real encoded data has.
    has_digit = any(c.isdigit() for c in stripped)
    has_upper = any(c.isupper() for c in stripped)
    has_lower = any(c.islower() for c in stripped)
    return sum((has_digit, has_upper, has_lower)) >= 2


def _looks_like_hex(data: str) -> bool:
    """Whether data is plausibly hex-encoded."""
    import re
    stripped = ''.join(data.split()).removeprefix('0x')
    return len(stripped) >= 8 and len(stripped) % 2 == 0 and bool(
        re.fullmatch(r'[0-9a-fA-F]+', stripped)
    )


def decode_gzip(data: str) -> str:
    """Decompress gzip data supplied as a latin-1 byte string."""
    import gzip
    return gzip.decompress(data.encode('latin-1')).decode('utf-8', errors='replace')


def decode_zlib(data: str) -> str:
    """Decompress zlib data supplied as a latin-1 byte string."""
    import zlib
    return zlib.decompress(data.encode('latin-1')).decode('utf-8', errors='replace')


def _decode_base64_bytes(data: str) -> bytes:
    """Decode base64 to raw bytes, preserving binary payloads."""
    data = ''.join(data.split()).replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)


def _try_decode(data: str, encoding: str) -> Optional[str]:
    """
    Attempt one decode step, returning None when it does not apply.

    Binary intermediates (base64 wrapping gzip, say) are carried as latin-1
    strings so no byte is lost between layers.
    """
    try:
        if encoding == 'gzip':
            return decode_gzip(data)
        if encoding == 'zlib':
            return decode_zlib(data)
        if encoding == 'base64':
            raw = _decode_base64_bytes(data)
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                # Not text: keep the exact bytes so a later gzip/zlib layer
                # can still read them.
                return raw.decode('latin-1')
        if encoding == 'hex':
            raw = bytes.fromhex(''.join(data.split()).removeprefix('0x'))
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return raw.decode('latin-1')
        return decode(data, encoding)
    except Exception:
        return None


def _is_compressed(data: str) -> Optional[str]:
    """Detect gzip/zlib magic bytes in a latin-1 carried string."""
    try:
        raw = data.encode('latin-1')
    except UnicodeEncodeError:
        return None
    if raw[:2] == b'\x1f\x8b':
        return 'gzip'
    # zlib: CMF/FLG where CMF low nibble is 8 and the pair is a multiple of 31
    if len(raw) > 2 and raw[0] & 0x0F == 8 and (raw[0] << 8 | raw[1]) % 31 == 0:
        return 'zlib'
    return None


def magic_decode(data: str, max_depth: int = 8) -> list:
    """
    Recursively auto-decode data until it stops looking encoded.

    At each step every candidate encoding is tried and the result that most
    improves readability wins. Returns the list of steps applied; an empty
    list means nothing decoded.
    """
    # Compression is checked first: its magic bytes are unambiguous.
    candidates = ['gzip', 'zlib', 'base64', 'hex', 'url', 'html', 'unicode-escape', 'punycode']
    steps = []
    current = data
    seen = {data}

    for _ in range(max_depth):
        best = None

        for encoding in candidates:
            # Cheap guards to avoid nonsense transforms.
            if encoding == 'url' and '%' not in current:
                continue
            if encoding == 'html' and '&' not in current:
                continue
            if encoding == 'unicode-escape' and '\\u' not in current:
                continue
            if encoding == 'punycode' and 'xn--' not in current:
                continue
            if encoding == 'base64' and not _looks_like_base64(current):
                continue
            if encoding == 'hex' and not _looks_like_hex(current):
                continue

            result = _try_decode(current, encoding)
            if not result or result == current or result in seen:
                continue

            score = _printable_ratio(result)
            # Unreadable output is normally a sign we decoded something that
            # was not encoded — unless it is recognisably compressed, in which
            # case the next layer will decompress it.
            if score < 0.95 and not _is_compressed(result):
                continue
            if _is_compressed(result):
                # Prefer following a compression layer over any text candidate.
                score = 2.0
            if best is None or score > best[1]:
                best = (encoding, score, result)

        if best is None:
            break

        encoding, score, result = best
        steps.append({
            'encoding': encoding,
            'output': result,
            'printable_ratio': round(score, 3),
        })
        seen.add(result)
        current = result

    return steps
