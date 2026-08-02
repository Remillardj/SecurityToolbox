"""
BSOT Utilities
Shared utilities for formatting, colors, and output.
"""

import hashlib


class Colors:
    """ANSI color codes for terminal output."""
    
    # Reset
    RESET = '\033[0m'
    
    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    @classmethod
    def disable(cls):
        """Disable colors (for non-terminal output)."""
        cls.RESET = ''
        cls.BLACK = ''
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.MAGENTA = ''
        cls.CYAN = ''
        cls.WHITE = ''
        cls.BRIGHT_BLACK = ''
        cls.BRIGHT_RED = ''
        cls.BRIGHT_GREEN = ''
        cls.BRIGHT_YELLOW = ''
        cls.BRIGHT_BLUE = ''
        cls.BRIGHT_MAGENTA = ''
        cls.BRIGHT_CYAN = ''
        cls.BRIGHT_WHITE = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.UNDERLINE = ''


def print_header(title: str):
    """Print a section header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  {title}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'═' * 60}{Colors.RESET}")


def print_subheader(title: str):
    """Print a subsection header."""
    print(f"\n{Colors.BLUE}── {title} ──{Colors.RESET}")


def print_finding(severity: str, message: str):
    """Print a security finding with severity coloring."""
    severity_colors = {
        'critical': Colors.RED + Colors.BOLD,
        'high': Colors.RED,
        'medium': Colors.YELLOW,
        'low': Colors.BLUE,
        'info': Colors.CYAN,
    }
    color = severity_colors.get(severity.lower(), Colors.WHITE)
    icon = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': 'ℹ️',
    }.get(severity.lower(), '•')
    
    print(f"  {icon} {color}[{severity.upper()}]{Colors.RESET} {message}")


def print_kv(key: str, value: str, indent: int = 2):
    """Print a key-value pair."""
    spaces = ' ' * indent
    print(f"{spaces}{Colors.CYAN}{key}:{Colors.RESET} {value}")


def format_bytes(size: int) -> str:
    """Format byte size to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def truncate(text: str, max_length: int = 50, suffix: str = '...') -> str:
    """Truncate text to max length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def hash_string(data: str, algorithm: str = 'sha256') -> str:
    """Hash a string."""
    return hashlib.new(algorithm, data.encode()).hexdigest()


def defang_url(url: str) -> str:
    """Defang a URL for safe display."""
    return url.replace('http://', 'hxxp://').replace('https://', 'hxxps://')


def defang_ip(ip: str) -> str:
    """Defang an IP address for safe display."""
    return ip.replace('.', '[.]')


def defang_domain(domain: str) -> str:
    """Defang a domain for safe display."""
    return domain.replace('.', '[.]')


def refang_url(url: str) -> str:
    """
    Refang a defanged URL.

    Handles the common separator variants as well as the plain form, so it is
    a true inverse of safe(): hxxp[://], hxxp[:]//, hxxps://, and [.] dots.
    """
    result = url
    for scheme in ('hxxps', 'hxxp'):
        replacement = 'https' if scheme == 'hxxps' else 'http'
        for separator in ('[://]', '[:]//', '://'):
            result = result.replace(f'{scheme}{separator}', f'{replacement}://')
    return result.replace('[.]', '.').replace('(.)', '.').replace('[dot]', '.')


def refang_ip(ip: str) -> str:
    """Refang a defanged IP address."""
    return ip.replace('[.]', '.')


def refang_domain(domain: str) -> str:
    """Refang a defanged domain."""
    return domain.replace('[.]', '.')


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def mask_sensitive(value: str, visible_chars: int = 4) -> str:
    """Mask sensitive data, showing only last N characters."""
    if len(value) <= visible_chars:
        return '*' * len(value)
    return '*' * (len(value) - visible_chars) + value[-visible_chars:]


def create_progress_bar(current: int, total: int, width: int = 40) -> str:
    """Create an ASCII progress bar."""
    if total == 0:
        percentage = 0
    else:
        percentage = current / total
    
    filled = int(width * percentage)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}] {percentage*100:.1f}%"


# Try to auto-detect terminal color support
import sys
import os

if not sys.stdout.isatty() or os.getenv('NO_COLOR'):
    Colors.disable()


# ---------------------------------------------------------------------------
# Safe display of indicators
#
# Human-readable output is routinely pasted into tickets, chat, and email,
# where a live URL is a click away from re-detonating a sample. Indicators are
# therefore defanged on the way out unless the caller opts out. JSON output is
# left intact: machine consumers need the real values.
# ---------------------------------------------------------------------------

import re as _re

_URL_SCHEME = _re.compile(r'\b(https?|ftp)://', _re.IGNORECASE)
_IPV4 = _re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b')
_DOMAIN = _re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+)'
    r'(com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|shop|live|icu|'
    r'dev|app|me|tv|cc|ws|pw|link|click|download|zip|mov|gq|tk|ml|ga|cf)\b',
    _re.IGNORECASE,
)

# Defanging is suppressed inside these so ordinary output stays readable.
_SAFE_HOSTS = frozenset({'localhost', '127.0.0.1', '0.0.0.0', '::1'})

_defang_enabled = True


def set_defang(enabled: bool) -> None:
    """Enable or disable defanging of human-readable output."""
    global _defang_enabled
    _defang_enabled = bool(enabled)


def defang_enabled() -> bool:
    return _defang_enabled


def safe(text: str) -> str:
    """
    Defang indicators in a string for safe display.

    Rewrites URL schemes and the dots in IPv4 addresses and domains, so the
    result cannot be clicked or resolved by accident.
    """
    if not _defang_enabled or not text:
        return text

    result = _URL_SCHEME.sub(lambda m: m.group(1).replace('t', 'x', 2) + '[://]', text)

    def _ip(match):
        if match.group(0) in _SAFE_HOSTS:
            return match.group(0)
        return '[.]'.join(match.groups())

    result = _IPV4.sub(_ip, result)

    def _domain(match):
        labels = match.group(1).rstrip('.')
        if labels.lower() in _SAFE_HOSTS:
            return match.group(0)
        return labels.replace('.', '[.]') + '[.]' + match.group(2)

    return _DOMAIN.sub(_domain, result)


def safe_echo(message: str = '', **kwargs):
    """click.echo() with indicators defanged."""
    import click

    click.echo(safe(message), **kwargs)
