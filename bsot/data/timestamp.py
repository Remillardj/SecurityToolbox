"""
Timestamp Utilities
Parse and convert between timestamp formats.
"""

import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class TimestampResult:
    """Parsed timestamp in multiple formats."""
    original: str
    valid: bool = True
    
    # Parsed datetime
    datetime: Optional[datetime] = None
    
    # Output formats
    unix: Optional[int] = None
    unix_ms: Optional[int] = None
    iso8601: str = ""
    human: str = ""
    relative: str = ""
    
    # Timezone
    timezone_name: str = "UTC"
    timezone_offset: str = "+00:00"
    
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'original': self.original,
            'valid': self.valid,
            'unix': self.unix,
            'unix_ms': self.unix_ms,
            'iso8601': self.iso8601,
            'human': self.human,
            'relative': self.relative,
            'timezone': self.timezone_name,
            'error': self.error,
        }


def parse_timestamp(value: str, tz: str = 'UTC') -> TimestampResult:
    """
    Parse a timestamp in various formats.
    
    Supported formats:
    - Unix epoch (seconds or milliseconds)
    - ISO8601
    - Common date formats (MM/DD/YYYY, DD-MM-YYYY, etc.)
    - Log formats
    
    Args:
        value: Timestamp string to parse
        tz: Target timezone (default: UTC)
        
    Returns:
        TimestampResult with all formats
    """
    result = TimestampResult(original=value)
    value = value.strip()
    
    dt = None
    
    # Try Unix epoch (seconds)
    if re.match(r'^\d{10}$', value):
        try:
            dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (ValueError, OSError):
            pass
    
    # Try Unix epoch (milliseconds)
    if not dt and re.match(r'^\d{13}$', value):
        try:
            dt = datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
        except (ValueError, OSError):
            pass
    
    # Try Unix epoch (microseconds)
    if not dt and re.match(r'^\d{16}$', value):
        try:
            dt = datetime.fromtimestamp(int(value) / 1000000, tz=timezone.utc)
        except (ValueError, OSError):
            pass
    
    # Try ISO8601 variants
    if not dt:
        iso_patterns = [
            r'%Y-%m-%dT%H:%M:%S.%fZ',
            r'%Y-%m-%dT%H:%M:%SZ',
            r'%Y-%m-%dT%H:%M:%S',
            r'%Y-%m-%d %H:%M:%S.%f',
            r'%Y-%m-%d %H:%M:%S',
            r'%Y-%m-%d',
        ]
        for pattern in iso_patterns:
            try:
                dt = datetime.strptime(value.rstrip('Z'), pattern.rstrip('Z'))
                if 'Z' in value or not dt.tzinfo:
                    dt = dt.replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    
    # Try common formats
    if not dt:
        common_patterns = [
            r'%m/%d/%Y %H:%M:%S',
            r'%m/%d/%Y %H:%M',
            r'%m/%d/%Y',
            r'%d/%m/%Y %H:%M:%S',
            r'%d/%m/%Y',
            r'%d-%m-%Y %H:%M:%S',
            r'%d-%m-%Y',
            r'%b %d %Y %H:%M:%S',
            r'%b %d, %Y %H:%M:%S',
            r'%B %d, %Y',
            r'%d %b %Y %H:%M:%S',
            r'%d %B %Y',
        ]
        for pattern in common_patterns:
            try:
                dt = datetime.strptime(value, pattern)
                dt = dt.replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    
    # Try log formats
    if not dt:
        log_patterns = [
            # Apache/Nginx combined log format
            (r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', r'%d/%b/%Y:%H:%M:%S'),
            # Syslog
            (r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', r'%b %d %H:%M:%S'),
        ]
        for regex, pattern in log_patterns:
            match = re.search(regex, value)
            if match:
                try:
                    dt = datetime.strptime(match.group(1), pattern)
                    # Add current year if not present
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    dt = dt.replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
    
    if not dt:
        result.valid = False
        result.error = "Could not parse timestamp"
        return result
    
    # Convert to target timezone
    try:
        import zoneinfo
        if tz.upper() != 'UTC':
            try:
                target_tz = zoneinfo.ZoneInfo(tz)
                dt = dt.astimezone(target_tz)
                result.timezone_name = tz
            except Exception:
                pass
    except ImportError:
        pass
    
    result.datetime = dt
    result.valid = True
    
    # Generate output formats
    result.unix = int(dt.timestamp())
    result.unix_ms = int(dt.timestamp() * 1000)
    result.iso8601 = dt.strftime('%Y-%m-%dT%H:%M:%S%z')
    result.human = dt.strftime('%B %d, %Y %I:%M:%S %p %Z')
    result.relative = _relative_time(dt)
    
    if dt.tzinfo:
        result.timezone_offset = dt.strftime('%z')
    
    return result


def convert_timestamp(
    value: str,
    output_format: str = 'all',
    tz: str = 'UTC'
) -> str:
    """
    Convert timestamp to specific format.
    
    Args:
        value: Timestamp to convert
        output_format: 'unix', 'unix-ms', 'iso', 'human', or 'all'
        tz: Target timezone
        
    Returns:
        Converted timestamp string
    """
    result = parse_timestamp(value, tz)
    
    if not result.valid:
        return f"Error: {result.error}"
    
    if output_format == 'unix':
        return str(result.unix)
    elif output_format == 'unix-ms':
        return str(result.unix_ms)
    elif output_format == 'iso':
        return result.iso8601
    elif output_format == 'human':
        return result.human
    else:
        lines = [
            f"Unix:    {result.unix}",
            f"Unix ms: {result.unix_ms}",
            f"ISO8601: {result.iso8601}",
            f"Human:   {result.human}",
            f"Relative: {result.relative}",
        ]
        return '\n'.join(lines)


def _relative_time(dt: datetime) -> str:
    """Calculate relative time string."""
    now = datetime.now(timezone.utc)
    diff = now - dt.astimezone(timezone.utc)
    
    seconds = abs(diff.total_seconds())
    is_future = diff.total_seconds() < 0
    
    if seconds < 60:
        unit = "seconds"
        value = int(seconds)
    elif seconds < 3600:
        unit = "minutes"
        value = int(seconds / 60)
    elif seconds < 86400:
        unit = "hours"
        value = int(seconds / 3600)
    elif seconds < 604800:
        unit = "days"
        value = int(seconds / 86400)
    elif seconds < 2629800:
        unit = "weeks"
        value = int(seconds / 604800)
    elif seconds < 31557600:
        unit = "months"
        value = int(seconds / 2629800)
    else:
        unit = "years"
        value = int(seconds / 31557600)
    
    if value == 1:
        unit = unit.rstrip('s')
    
    if is_future:
        return f"in {value} {unit}"
    else:
        return f"{value} {unit} ago"


def now_formats() -> Dict[str, Any]:
    """Get current time in all formats."""
    now = datetime.now(timezone.utc)
    return {
        'unix': int(now.timestamp()),
        'unix_ms': int(now.timestamp() * 1000),
        'iso8601': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'human': now.strftime('%B %d, %Y %I:%M:%S %p UTC'),
        'date': now.strftime('%Y-%m-%d'),
        'time': now.strftime('%H:%M:%S'),
    }

