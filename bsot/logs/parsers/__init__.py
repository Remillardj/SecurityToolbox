"""
Log Parsers
Support for various log formats.
"""

import gzip
import re
from pathlib import Path
from typing import List, Optional, Iterator
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LogEvent:
    """Normalized log event."""
    timestamp: Optional[datetime] = None
    timestamp_str: str = ""
    source: str = ""
    source_type: str = ""
    host: str = ""
    severity: str = ""
    event_type: str = ""
    event_action: str = ""
    user: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    message: str = ""
    raw: str = ""
    extra: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else self.timestamp_str,
            'source': self.source,
            'source_type': self.source_type,
            'host': self.host,
            'severity': self.severity,
            'event_type': self.event_type,
            'event_action': self.event_action,
            'user': self.user,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'message': self.message,
            'raw': self.raw,
            'extra': self.extra,
        }


def detect_format(file_path: str) -> str:
    """
    Detect log format from file content.
    
    Returns: syslog, json, clf, cef, evtx, auto
    """
    path = Path(file_path)
    
    # Check extension
    if path.suffix.lower() == '.evtx':
        return 'evtx'
    
    if path.suffix.lower() in ('.json', '.jsonl'):
        return 'json'
    
    # Read first few lines
    try:
        opener = gzip.open if path.suffix.lower() == '.gz' else open
        with opener(path, 'rt', errors='replace') as f:
            lines = [f.readline() for _ in range(5)]
            sample = ''.join(lines)
    except Exception:
        return 'auto'
    
    # Check for JSON
    if sample.strip().startswith('{') or sample.strip().startswith('['):
        return 'json'
    
    # Check for CEF
    if 'CEF:' in sample:
        return 'cef'
    
    # Check for CLF (Common Log Format)
    clf_pattern = r'^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\['
    if re.search(clf_pattern, sample):
        return 'clf'
    
    # Check for syslog
    syslog_pattern = r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}'
    if re.search(syslog_pattern, sample):
        return 'syslog'
    
    return 'auto'


def parse_log(file_path: str, format: str = 'auto', limit: int = None) -> List[LogEvent]:
    """
    Parse log file into normalized events.
    
    Args:
        file_path: Path to log file
        format: Log format (auto-detect if not specified)
        limit: Maximum events to parse
        
    Returns:
        List of LogEvent
    """
    if format == 'auto':
        format = detect_format(file_path)
    
    events = []
    path = Path(file_path)
    
    # Handle gzip
    opener = gzip.open if path.suffix.lower() == '.gz' else open
    
    try:
        with opener(path, 'rt', errors='replace') as f:
            if format == 'json':
                events = list(_parse_json(f, path.name, limit))
            elif format == 'syslog':
                events = list(_parse_syslog(f, path.name, limit))
            elif format == 'clf':
                events = list(_parse_clf(f, path.name, limit))
            elif format == 'cef':
                events = list(_parse_cef(f, path.name, limit))
            else:
                events = list(_parse_generic(f, path.name, limit))
    except Exception as e:
        # Return empty list on error
        pass
    
    return events


def _parse_json(f, source: str, limit: int) -> Iterator[LogEvent]:
    """Parse JSON/JSONL logs."""
    import json
    
    count = 0
    for line in f:
        if limit and count >= limit:
            break
        
        line = line.strip()
        if not line:
            continue
        
        try:
            data = json.loads(line)
            
            event = LogEvent(
                source=source,
                source_type='json',
                raw=line
            )
            
            # Try common timestamp fields
            for ts_field in ['timestamp', '@timestamp', 'time', 'datetime', 'date']:
                if ts_field in data:
                    event.timestamp_str = str(data[ts_field])
                    break
            
            # Try common field mappings
            event.message = data.get('message', data.get('msg', ''))
            event.severity = data.get('level', data.get('severity', data.get('log_level', '')))
            event.host = data.get('host', data.get('hostname', ''))
            event.source_ip = data.get('source_ip', data.get('src_ip', data.get('client_ip', '')))
            event.user = data.get('user', data.get('username', ''))
            event.extra = data
            
            yield event
            count += 1
            
        except json.JSONDecodeError:
            continue


def _parse_syslog(f, source: str, limit: int) -> Iterator[LogEvent]:
    """Parse syslog format."""
    # Syslog pattern: Mar 15 10:30:45 hostname process[pid]: message
    pattern = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )
    
    count = 0
    for line in f:
        if limit and count >= limit:
            break
        
        line = line.strip()
        if not line:
            continue
        
        match = pattern.match(line)
        if match:
            event = LogEvent(
                timestamp_str=match.group('timestamp'),
                host=match.group('host'),
                message=match.group('message'),
                source=source,
                source_type='syslog',
                raw=line
            )
            event.extra = {
                'process': match.group('process'),
                'pid': match.group('pid')
            }
            
            # Detect authentication events
            msg_lower = event.message.lower()
            if 'failed' in msg_lower and ('password' in msg_lower or 'auth' in msg_lower):
                event.event_type = 'authentication'
                event.event_action = 'failure'
            elif 'accepted' in msg_lower or 'successful' in msg_lower:
                event.event_type = 'authentication'
                event.event_action = 'success'
            
            # Extract IP from message
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', event.message)
            if ip_match:
                event.source_ip = ip_match.group(1)
            
            # Extract user
            user_match = re.search(r'for\s+(?:user\s+)?(\S+)', event.message)
            if user_match:
                event.user = user_match.group(1)
            
            yield event
            count += 1
        else:
            yield LogEvent(message=line, source=source, source_type='syslog', raw=line)
            count += 1


def _parse_clf(f, source: str, limit: int) -> Iterator[LogEvent]:
    """Parse Common Log Format (Apache/Nginx)."""
    # CLF: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    pattern = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\S+)'
    )
    
    count = 0
    for line in f:
        if limit and count >= limit:
            break
        
        line = line.strip()
        if not line:
            continue
        
        match = pattern.match(line)
        if match:
            event = LogEvent(
                source_ip=match.group('ip'),
                timestamp_str=match.group('timestamp'),
                user=match.group('user') if match.group('user') != '-' else '',
                message=match.group('request'),
                source=source,
                source_type='clf',
                raw=line
            )
            event.extra = {
                'status': match.group('status'),
                'size': match.group('size'),
                'request': match.group('request')
            }
            event.event_type = 'web'
            
            yield event
            count += 1


def _parse_cef(f, source: str, limit: int) -> Iterator[LogEvent]:
    """Parse CEF (Common Event Format)."""
    count = 0
    for line in f:
        if limit and count >= limit:
            break
        
        line = line.strip()
        if 'CEF:' not in line:
            continue
        
        # Extract CEF header
        cef_start = line.find('CEF:')
        cef_content = line[cef_start:]
        
        # Split by pipe
        parts = cef_content.split('|')
        if len(parts) >= 8:
            event = LogEvent(
                source=source,
                source_type='cef',
                raw=line
            )
            event.extra = {
                'version': parts[0].replace('CEF:', ''),
                'vendor': parts[1],
                'product': parts[2],
                'version': parts[3],
                'signature_id': parts[4],
                'name': parts[5],
                'severity': parts[6],
            }
            event.severity = parts[6]
            event.message = parts[5]
            
            # Parse extension fields (key=value pairs)
            if len(parts) > 7:
                ext = parts[7]
                for kv in re.findall(r'(\w+)=([^\s]+)', ext):
                    event.extra[kv[0]] = kv[1]
                    if kv[0] in ('src', 'sourceAddress'):
                        event.source_ip = kv[1]
                    elif kv[0] in ('dst', 'destinationAddress'):
                        event.destination_ip = kv[1]
                    elif kv[0] in ('suser', 'sourceUser'):
                        event.user = kv[1]
            
            yield event
            count += 1


def _parse_generic(f, source: str, limit: int) -> Iterator[LogEvent]:
    """Generic line-by-line parsing."""
    count = 0
    for line in f:
        if limit and count >= limit:
            break
        
        line = line.strip()
        if not line:
            continue
        
        event = LogEvent(
            message=line,
            source=source,
            source_type='generic',
            raw=line
        )
        
        # Try to extract timestamp from start
        ts_match = re.match(r'^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
        if ts_match:
            event.timestamp_str = ts_match.group(1)
        
        # Extract IPs
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
        if ips:
            event.source_ip = ips[0]
        
        yield event
        count += 1

