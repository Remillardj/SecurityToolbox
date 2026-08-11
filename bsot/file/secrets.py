"""
Secret Scanner
Detect hardcoded credentials, API keys, and secrets in files.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass, field


@dataclass
class SecretFinding:
    """A detected secret."""
    file_path: str
    line_number: int
    secret_type: str
    match: str
    line_content: str
    confidence: str  # high, medium, low
    
    def to_dict(self) -> dict:
        return {
            'file': self.file_path,
            'line': self.line_number,
            'type': self.secret_type,
            'match': self.match,
            'content': self.line_content.strip(),
            'confidence': self.confidence,
        }


@dataclass 
class ScanResult:
    """Result of a secret scan."""
    files_scanned: int = 0
    files_with_secrets: int = 0
    total_findings: int = 0
    findings: List[SecretFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'files_scanned': self.files_scanned,
            'files_with_secrets': self.files_with_secrets,
            'total_findings': self.total_findings,
            'findings': [f.to_dict() for f in self.findings],
            'errors': self.errors,
        }


class SecretScanner:
    """
    Scan files for hardcoded secrets and credentials.
    
    Detects:
    - API keys (AWS, GCP, Azure, GitHub, Slack, etc.)
    - Private keys (RSA, DSA, EC, PGP)
    - Database connection strings
    - Passwords in code
    - JWT tokens
    - Generic high-entropy strings
    """
    
    # Secret patterns with confidence levels
    PATTERNS = {
        # AWS
        'aws_access_key': {
            'pattern': re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
            'confidence': 'high',
        },
        'aws_secret_key': {
            'pattern': re.compile(r'(?i)aws_?(?:secret_?)?(?:access_?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
            'confidence': 'high',
        },
        
        # GitHub
        'github_token': {
            'pattern': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            'confidence': 'high',
        },
        'github_oauth': {
            'pattern': re.compile(r'github_pat_[A-Za-z0-9_]{22,}'),
            'confidence': 'high',
        },
        
        # Slack
        'slack_token': {
            'pattern': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
            'confidence': 'high',
        },
        'slack_webhook': {
            'pattern': re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
            'confidence': 'high',
        },
        
        # Google/GCP
        'gcp_api_key': {
            'pattern': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
            'confidence': 'high',
        },
        'gcp_service_account': {
            'pattern': re.compile(r'"type"\s*:\s*"service_account"'),
            'confidence': 'high',
        },
        
        # Azure
        'azure_storage_key': {
            'pattern': re.compile(r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86}'),
            'confidence': 'high',
        },
        
        # Stripe
        'stripe_api_key': {
            'pattern': re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),
            'confidence': 'high',
        },
        
        # Twilio
        'twilio_api_key': {
            'pattern': re.compile(r'SK[0-9a-fA-F]{32}'),
            'confidence': 'medium',
        },
        
        # SendGrid
        'sendgrid_api_key': {
            'pattern': re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
            'confidence': 'high',
        },
        
        # Mailgun
        'mailgun_api_key': {
            'pattern': re.compile(r'key-[0-9a-zA-Z]{32}'),
            'confidence': 'medium',
        },
        
        # Private Keys
        'private_key_rsa': {
            'pattern': re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
            'confidence': 'high',
        },
        'private_key_dsa': {
            'pattern': re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
            'confidence': 'high',
        },
        'private_key_ec': {
            'pattern': re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
            'confidence': 'high',
        },
        'private_key_openssh': {
            'pattern': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
            'confidence': 'high',
        },
        'private_key_pgp': {
            'pattern': re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
            'confidence': 'high',
        },
        
        # JWT
        'jwt_token': {
            'pattern': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            'confidence': 'medium',
        },
        
        # Database URLs
        'database_url': {
            'pattern': re.compile(r'(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s<>"\']+:[^\s<>"\']+@[^\s<>"\']+'),
            'confidence': 'high',
        },
        
        # Generic patterns
        'password_assignment': {
            'pattern': re.compile(r'(?i)(?:password|passwd|pwd|secret|token|api_?key|auth_?token)\s*[:=]\s*["\'][^"\']{8,}["\']'),
            'confidence': 'medium',
        },
        'bearer_token': {
            'pattern': re.compile(r'(?i)bearer\s+[a-zA-Z0-9_-]{20,}'),
            'confidence': 'medium',
        },
        'basic_auth': {
            'pattern': re.compile(r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}'),
            'confidence': 'medium',
        },
        
        # NPM
        'npm_token': {
            'pattern': re.compile(r'//registry\.npmjs\.org/:_authToken=[^\s]+'),
            'confidence': 'high',
        },
        
        # PyPI
        'pypi_token': {
            'pattern': re.compile(r'pypi-[A-Za-z0-9_-]{100,}'),
            'confidence': 'high',
        },
        
        # Heroku
        'heroku_api_key': {
            'pattern': re.compile(r'(?i)heroku[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            'confidence': 'high',
        },
        
        # Discord
        'discord_token': {
            'pattern': re.compile(r'(?:mfa\.)?[a-zA-Z0-9_-]{24,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}'),
            'confidence': 'medium',
        },
        'discord_webhook': {
            'pattern': re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'),
            'confidence': 'high',
        },
        
        # Generic API key pattern
        'generic_api_key': {
            'pattern': re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}["\']?'),
            'confidence': 'low',
        },
    }
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.cpp', '.c', '.h', '.rs', '.swift', '.kt', '.scala',
        '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
        '.yml', '.yaml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf',
        '.env', '.properties', '.tf', '.tfvars',
        '.md', '.txt', '.rst',
        '.sql', '.graphql',
        '.dockerfile', 'Dockerfile',
        '.html', '.htm', '.css', '.scss', '.sass',
    }
    
    # Files to always scan regardless of extension
    ALWAYS_SCAN = {
        '.env', '.env.local', '.env.development', '.env.production',
        '.npmrc', '.pypirc', '.netrc', '.gitconfig',
        'credentials', 'secrets', 'config',
    }
    
    # Directories to skip
    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.venv', 'venv',
        'vendor', 'target', 'build', 'dist', '.idea', '.vscode',
        'coverage', '.coverage', 'htmlcov', '.pytest_cache', '.mypy_cache',
    }
    
    # Files to skip
    SKIP_FILES = {
        'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock',
        'go.sum', 'composer.lock', 'Gemfile.lock',
    }
    
    def __init__(
        self,
        include_low_confidence: bool = False,
        custom_patterns: Dict[str, Dict] = None,
        exclude_patterns: List[str] = None,
    ):
        """
        Initialize secret scanner.
        
        Args:
            include_low_confidence: Include low-confidence findings
            custom_patterns: Additional patterns to check
            exclude_patterns: Pattern names to exclude
        """
        self.include_low_confidence = include_low_confidence
        self.patterns = dict(self.PATTERNS)
        
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        if exclude_patterns:
            for name in exclude_patterns:
                self.patterns.pop(name, None)
    
    def scan_file(self, file_path: str) -> List[SecretFinding]:
        """
        Scan a single file for secrets.
        
        Args:
            file_path: Path to file
            
        Returns:
            List of findings
        """
        findings = []
        path = Path(file_path)
        
        try:
            content = path.read_text(errors='ignore')
        except (IOError, OSError):
            return findings
        
        for line_num, line in enumerate(content.splitlines(), 1):
            for name, config in self.patterns.items():
                if not self.include_low_confidence and config['confidence'] == 'low':
                    continue
                
                for match in config['pattern'].finditer(line):
                    # Avoid duplicates
                    finding = SecretFinding(
                        file_path=str(path),
                        line_number=line_num,
                        secret_type=name,
                        match=self._redact(match.group()),
                        line_content=line,
                        confidence=config['confidence'],
                    )
                    findings.append(finding)
        
        return findings
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        file_extensions: Set[str] = None,
    ) -> ScanResult:
        """
        Scan a directory for secrets.
        
        Args:
            directory: Directory path
            recursive: Scan subdirectories
            file_extensions: Limit to specific extensions
            
        Returns:
            ScanResult
        """
        result = ScanResult()
        root = Path(directory)
        
        if not root.exists():
            result.errors.append(f"Directory not found: {directory}")
            return result
        
        extensions = file_extensions or self.SCANNABLE_EXTENSIONS
        files_with_findings: Set[str] = set()
        
        # Get files to scan
        if recursive:
            files = root.rglob('*')
        else:
            files = root.glob('*')
        
        for file_path in files:
            if not file_path.is_file():
                continue
            
            # Skip directories
            if any(skip in file_path.parts for skip in self.SKIP_DIRS):
                continue
            
            # Skip certain files
            if file_path.name in self.SKIP_FILES:
                continue
            
            # Check extension
            should_scan = (
                file_path.suffix.lower() in extensions or
                file_path.name in self.ALWAYS_SCAN or
                any(name in file_path.name.lower() for name in self.ALWAYS_SCAN)
            )
            
            if not should_scan:
                continue
            
            result.files_scanned += 1
            
            try:
                findings = self.scan_file(str(file_path))
                if findings:
                    files_with_findings.add(str(file_path))
                    result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"{file_path}: {e}")
        
        result.files_with_secrets = len(files_with_findings)
        result.total_findings = len(result.findings)
        
        return result
    
    def _redact(self, secret: str, show_chars: int = 4) -> str:
        """Partially redact a secret for safe display."""
        if len(secret) <= show_chars * 2:
            return '*' * len(secret)
        return secret[:show_chars] + '*' * (len(secret) - show_chars * 2) + secret[-show_chars:]


BASELINE_VERSION = 1


def _relative_to_root(file_path: str, root: str) -> str:
    return Path(os.path.relpath(file_path, root)).as_posix()


def fingerprint_finding(finding: SecretFinding, root: str) -> str:
    """
    Stable identity for a known finding: scan-root-relative path, pattern
    name, and the redacted match. Line numbers are deliberately excluded so
    unrelated edits that shift lines do not invalidate a baseline, and the
    path is relative so a baseline written on one machine holds in CI.
    """
    rel = _relative_to_root(finding.file_path, root)
    material = '\n'.join((rel, finding.secret_type, finding.match))
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def write_baseline(baseline_path: str, findings: List[SecretFinding], root: str) -> int:
    """Record fingerprints of the given findings. Returns the count written."""
    entries = {}
    for finding in findings:
        fp = fingerprint_finding(finding, root)
        entries[fp] = {
            'file': _relative_to_root(finding.file_path, root),
            'type': finding.secret_type,
            'fingerprint': fp,
        }
    payload = {
        'version': BASELINE_VERSION,
        'findings': sorted(
            entries.values(),
            key=lambda e: (e['file'], e['type'], e['fingerprint']),
        ),
    }
    Path(baseline_path).write_text(json.dumps(payload, indent=2) + '\n')
    return len(entries)


def load_baseline(baseline_path: str) -> Set[str]:
    """Return the set of suppressed fingerprints from a baseline file."""
    payload = json.loads(Path(baseline_path).read_text())
    if payload.get('version') != BASELINE_VERSION:
        raise ValueError(f"unsupported baseline version: {payload.get('version')!r}")
    return {entry['fingerprint'] for entry in payload.get('findings', [])}

