"""
Log Analyzers
Attack detection and pattern analysis.
"""

from typing import List, Dict, Any
from dataclasses import dataclass, field
from collections import defaultdict

import re


@dataclass
class Finding:
    """Security finding from log analysis."""
    type: str  # brute_force, privilege_escalation, lateral_movement, etc.
    severity: str  # critical, high, medium, low
    description: str
    mitre_technique: str = ""
    source_ip: str = ""
    target_user: str = ""
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'type': self.type,
            'severity': self.severity,
            'description': self.description,
            'mitre_technique': self.mitre_technique,
            'source_ip': self.source_ip,
            'target_user': self.target_user,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'event_count': self.event_count,
            'evidence': self.evidence[:5],  # Limit evidence
        }


@dataclass
class AnalysisResult:
    """Complete log analysis result."""
    total_events: int = 0
    time_range: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            'total_events': self.total_events,
            'time_range': self.time_range,
            'findings': [f.to_dict() for f in self.findings],
            'statistics': self.statistics,
        }


def analyze_logs(
    events: List,
    checks: List[str] = None,
    include_mitre: bool = True
) -> AnalysisResult:
    """
    Analyze log events for security issues.
    
    Args:
        events: List of LogEvent objects
        checks: Which checks to run (brute_force, privesc, lateral, anomaly)
        include_mitre: Tag findings with MITRE ATT&CK IDs
        
    Returns:
        AnalysisResult
    """
    if checks is None:
        checks = ['brute_force', 'privesc', 'lateral', 'anomaly']
    
    result = AnalysisResult(total_events=len(events))
    
    if not events:
        return result
    
    # Calculate time range
    timestamps = [e.timestamp_str for e in events if e.timestamp_str]
    if timestamps:
        result.time_range = {
            'start': min(timestamps),
            'end': max(timestamps)
        }
    
    # Run detection checks
    if 'brute_force' in checks:
        result.findings.extend(_detect_brute_force(events))
    
    if 'privesc' in checks:
        result.findings.extend(_detect_privilege_escalation(events))
    
    if 'lateral' in checks:
        result.findings.extend(_detect_lateral_movement(events))
    
    if 'anomaly' in checks:
        result.findings.extend(_detect_anomalies(events))
    
    # Calculate statistics
    result.statistics = _calculate_statistics(events)
    
    return result


def _detect_brute_force(events: List) -> List[Finding]:
    """Detect brute force attacks."""
    findings = []
    
    # Track failed logins per IP
    failed_by_ip = defaultdict(list)
    
    # Track same password across users (password spray)
    failures_by_user = defaultdict(list)
    
    for event in events:
        if event.event_action == 'failure' and event.event_type == 'authentication':
            if event.source_ip:
                failed_by_ip[event.source_ip].append(event)
            if event.user:
                failures_by_user[event.user].append(event)
    
    # Check for brute force (>5 failures from same IP)
    for ip, failures in failed_by_ip.items():
        if len(failures) >= 5:
            finding = Finding(
                type='brute_force',
                severity='high' if len(failures) >= 10 else 'medium',
                description=f"{len(failures)} failed login attempts from {ip}",
                mitre_technique='T1110.001',  # Brute Force: Password Guessing
                source_ip=ip,
                event_count=len(failures),
                first_seen=failures[0].timestamp_str,
                last_seen=failures[-1].timestamp_str,
                evidence=[f.raw for f in failures[:5]]
            )
            
            # Get targeted users
            users = set(f.user for f in failures if f.user)
            if users:
                finding.target_user = ', '.join(list(users)[:3])
            
            findings.append(finding)
    
    # Check for password spray (same user targeted by multiple IPs)
    for user, failures in failures_by_user.items():
        ips = set(f.source_ip for f in failures if f.source_ip)
        if len(ips) >= 3:
            findings.append(Finding(
                type='password_spray',
                severity='high',
                description=f"User {user} targeted by {len(ips)} different IPs",
                mitre_technique='T1110.003',  # Password Spraying
                target_user=user,
                event_count=len(failures),
                first_seen=failures[0].timestamp_str,
                last_seen=failures[-1].timestamp_str,
                evidence=[f.raw for f in failures[:5]]
            ))
    
    return findings


def _detect_privilege_escalation(events: List) -> List[Finding]:
    """Detect privilege escalation attempts."""
    findings = []
    
    priv_patterns = [
        (r'sudo', 'sudo usage'),
        (r'su\s+', 'su command'),
        (r'chmod.*[47]', 'permission change'),
        (r'chown.*root', 'ownership to root'),
        (r'usermod.*-aG.*sudo', 'adding to sudo group'),
        (r'passwd\s+root', 'root password change'),
        (r'visudo', 'sudoers modification'),
    ]
    
    for event in events:
        msg = event.message.lower() if event.message else ''
        
        for pattern, desc in priv_patterns:
            if re.search(pattern, msg, re.IGNORECASE):
                findings.append(Finding(
                    type='privilege_escalation',
                    severity='medium',
                    description=f"Privilege escalation activity: {desc}",
                    mitre_technique='T1548',  # Abuse Elevation Control Mechanism
                    source_ip=event.source_ip,
                    target_user=event.user,
                    event_count=1,
                    first_seen=event.timestamp_str,
                    evidence=[event.raw]
                ))
                break
    
    return findings


def _detect_lateral_movement(events: List) -> List[Finding]:
    """Detect lateral movement patterns."""
    findings = []
    
    # Track SSH connections between internal hosts
    ssh_events = []
    
    for event in events:
        msg = event.message.lower() if event.message else ''
        
        if 'ssh' in msg or 'sshd' in str(event.extra.get('process', '')):
            if event.event_action == 'success':
                ssh_events.append(event)
    
    # Look for successful SSH from internal IPs
    for event in ssh_events:
        if event.source_ip and _is_internal_ip(event.source_ip):
            findings.append(Finding(
                type='lateral_movement',
                severity='medium',
                description=f"SSH connection from internal IP {event.source_ip}",
                mitre_technique='T1021.004',  # Remote Services: SSH
                source_ip=event.source_ip,
                target_user=event.user,
                event_count=1,
                first_seen=event.timestamp_str,
                evidence=[event.raw]
            ))
    
    return findings


def _detect_anomalies(events: List) -> List[Finding]:
    """Detect various anomalies."""
    findings = []
    
    # Track events by hour
    hourly_counts = defaultdict(int)
    
    for event in events:
        ts = event.timestamp_str
        if ts:
            # Try to extract hour
            hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', ts)
            if hour_match:
                hour = int(hour_match.group(1))
                hourly_counts[hour] += 1
    
    # Check for off-hours activity (11 PM - 5 AM)
    off_hours_count = sum(hourly_counts[h] for h in range(23, 24)) + sum(hourly_counts[h] for h in range(0, 6))
    total = sum(hourly_counts.values())
    
    if total > 0 and off_hours_count / total > 0.3:
        findings.append(Finding(
            type='off_hours_activity',
            severity='low',
            description=f"Significant activity during off-hours ({off_hours_count} events)",
            event_count=off_hours_count,
        ))
    
    return findings


def _calculate_statistics(events: List) -> Dict[str, Any]:
    """Calculate event statistics."""
    stats = {
        'event_types': defaultdict(int),
        'source_ips': defaultdict(int),
        'users': defaultdict(int),
        'severities': defaultdict(int),
        'auth_success': 0,
        'auth_failure': 0,
    }
    
    for event in events:
        if event.event_type:
            stats['event_types'][event.event_type] += 1
        if event.source_ip:
            stats['source_ips'][event.source_ip] += 1
        if event.user:
            stats['users'][event.user] += 1
        if event.severity:
            stats['severities'][event.severity] += 1
        
        if event.event_type == 'authentication':
            if event.event_action == 'success':
                stats['auth_success'] += 1
            elif event.event_action == 'failure':
                stats['auth_failure'] += 1
    
    # Convert to regular dicts and limit
    stats['event_types'] = dict(stats['event_types'])
    stats['source_ips'] = dict(sorted(stats['source_ips'].items(), key=lambda x: -x[1])[:20])
    stats['users'] = dict(sorted(stats['users'].items(), key=lambda x: -x[1])[:20])
    stats['severities'] = dict(stats['severities'])
    
    return stats


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private."""
    if not ip:
        return False
    
    # Check private ranges
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
    ]
    
    for pattern in private_patterns:
        if re.match(pattern, ip):
            return True
    
    return False

