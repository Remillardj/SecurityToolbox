#!/usr/bin/env python3
"""
File security analysis commands
"""

import click
import os
import re
import hashlib
from pathlib import Path

@click.group('file')
def file_group():
    """File security analysis tools"""
    pass

@file_group.command('permissions')
@click.argument('directory')
@click.option('-r', '--recursive', is_flag=True, default=True, help='Scan recursively (default: True)')
@click.option('-v', '--verbose', is_flag=True, help='Show all files, not just risky ones')
def permissions(directory, recursive, verbose):
    """Scan for files with overly permissive permissions

    Examples:
        bsot file permissions /var/www
        bsot file permissions /home/user --verbose
    """
    monitored_octal_permissions = [
        '777', '666', '755', '775', '707', '757', '767'
    ]

    click.echo(f"Scanning directory: {directory}")
    click.echo("=" * 60)

    risky_count = 0
    total_count = 0

    if recursive:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    octal_permissions = oct(os.stat(file_path).st_mode)[-3:]
                    total_count += 1

                    if octal_permissions in monitored_octal_permissions:
                        click.echo(f'⚠️  {octal_permissions} - {file_path}')
                        risky_count += 1
                    elif verbose:
                        click.echo(f'✅ {octal_permissions} - {file_path}')
                except (PermissionError, FileNotFoundError) as e:
                    if verbose:
                        click.echo(f"Error: {file_path} - {e}", err=True)
    else:
        try:
            for item in os.listdir(directory):
                file_path = os.path.join(directory, item)
                if os.path.isfile(file_path):
                    octal_permissions = oct(os.stat(file_path).st_mode)[-3:]
                    total_count += 1

                    if octal_permissions in monitored_octal_permissions:
                        click.echo(f'⚠️  {octal_permissions} - {file_path}')
                        risky_count += 1
                    elif verbose:
                        click.echo(f'✅ {octal_permissions} - {file_path}')
        except (PermissionError, FileNotFoundError) as e:
            click.echo(f"Error: {e}", err=True)
            return

    click.echo("=" * 60)
    click.echo(f"Scan complete: {risky_count} risky file(s) found out of {total_count} total")

@file_group.command('suid-finder')
@click.argument('directory', default='/')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed information')
def suid_finder(directory, verbose):
    """Find SUID/SGID binaries that could be privilege escalation vectors

    Examples:
        bsot file suid-finder
        bsot file suid-finder /usr/bin
        bsot file suid-finder / --verbose
    """
    import stat

    click.echo(f"Scanning for SUID/SGID binaries in: {directory}")
    click.echo("=" * 60)

    suid_files = []
    sgid_files = []

    try:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_stat = os.stat(file_path)
                    mode = file_stat.st_mode

                    # Check for SUID bit
                    if mode & stat.S_ISUID:
                        suid_files.append({
                            'path': file_path,
                            'owner': file_stat.st_uid,
                            'permissions': oct(mode)[-4:]
                        })

                    # Check for SGID bit
                    if mode & stat.S_ISGID:
                        sgid_files.append({
                            'path': file_path,
                            'owner': file_stat.st_uid,
                            'permissions': oct(mode)[-4:]
                        })
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    except KeyboardInterrupt:
        click.echo("\nScan interrupted by user")

    # Display results
    if suid_files:
        click.echo(f"\n🔴 SUID BINARIES FOUND ({len(suid_files)}):")
        for file in suid_files:
            click.echo(f"  {file['permissions']} - {file['path']}")
            if verbose:
                click.echo(f"    Owner UID: {file['owner']}")

    if sgid_files:
        click.echo(f"\n🟡 SGID BINARIES FOUND ({len(sgid_files)}):")
        for file in sgid_files:
            click.echo(f"  {file['permissions']} - {file['path']}")
            if verbose:
                click.echo(f"    Owner UID: {file['owner']}")

    click.echo("=" * 60)
    click.echo(f"Scan complete: {len(suid_files)} SUID, {len(sgid_files)} SGID binaries found")

@file_group.command('cred-scan')
@click.argument('path', default='.')
@click.option('-r', '--recursive', is_flag=True, default=True, help='Scan recursively (default: true)')
@click.option('--no-recursive', is_flag=True, help='Disable recursive scanning')
@click.option('-l', '--include-low', is_flag=True, help='Include low-confidence findings')
@click.option('--json', 'json_output', is_flag=True, help='JSON output for CI/CD')
@click.option('-q', '--quiet', is_flag=True, help='Only output on findings (for CI)')
@click.option('-v', '--verbose', is_flag=True, help='Show files being scanned')
def cred_scan(path, recursive, no_recursive, include_low, json_output, quiet, verbose):
    """Scan files for hardcoded credentials and secrets

    Detects API keys, private keys, passwords, tokens, and other secrets
    in source code and configuration files.

    Exit codes:
      0 - No secrets found
      1 - Secrets detected  
      2 - Error

    Examples:
        bsot file cred-scan .
        bsot file cred-scan src/ --json
        bsot file cred-scan . --include-low
        
    CI/CD Usage:
        bsot file cred-scan . --quiet --json > secrets.json || exit 1
    """
    import json
    import sys
    
    # Comprehensive secret patterns with confidence levels
    PATTERNS = {
        # AWS (HIGH)
        'aws_access_key': (re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'), 'high'),
        'aws_secret_key': (re.compile(r'(?i)aws_?(?:secret_?)?(?:access_?)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), 'high'),
        
        # GitHub (HIGH)
        'github_token': (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), 'high'),
        'github_oauth': (re.compile(r'github_pat_[A-Za-z0-9_]{22,}'), 'high'),
        
        # Slack (HIGH)
        'slack_token': (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'), 'high'),
        'slack_webhook': (re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'), 'high'),
        
        # Google/GCP (HIGH)
        'gcp_api_key': (re.compile(r'AIza[0-9A-Za-z_-]{35}'), 'high'),
        'gcp_service_account': (re.compile(r'"type"\s*:\s*"service_account"'), 'high'),
        
        # Stripe (HIGH)
        'stripe_api_key': (re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'), 'high'),
        
        # SendGrid (HIGH)
        'sendgrid_api_key': (re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'), 'high'),
        
        # Private Keys (HIGH)
        'private_key_rsa': (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), 'high'),
        'private_key_dsa': (re.compile(r'-----BEGIN DSA PRIVATE KEY-----'), 'high'),
        'private_key_ec': (re.compile(r'-----BEGIN EC PRIVATE KEY-----'), 'high'),
        'private_key_openssh': (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), 'high'),
        'private_key_pgp': (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), 'high'),
        
        # Database URLs (HIGH)
        'database_url': (re.compile(r'(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^\s<>"\']+:[^\s<>"\']+@[^\s<>"\']+'), 'high'),
        
        # NPM/PyPI (HIGH)
        'npm_token': (re.compile(r'//registry\.npmjs\.org/:_authToken=[^\s]+'), 'high'),
        'pypi_token': (re.compile(r'pypi-[A-Za-z0-9_-]{100,}'), 'high'),
        
        # Discord (HIGH/MEDIUM)
        'discord_webhook': (re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'), 'high'),
        'discord_token': (re.compile(r'(?:mfa\.)?[a-zA-Z0-9_-]{24,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}'), 'medium'),
        
        # JWT (MEDIUM)
        'jwt_token': (re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'), 'medium'),
        
        # Generic patterns (MEDIUM/LOW)
        'password_assignment': (re.compile(r'(?i)(?:password|passwd|pwd|secret|token|api_?key|auth_?token)\s*[:=]\s*["\'][^"\']{8,}["\']'), 'medium'),
        'bearer_token': (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_-]{20,}'), 'medium'),
        'basic_auth': (re.compile(r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}'), 'medium'),
        'generic_api_key': (re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}["\']?'), 'low'),
    }
    
    # File extensions to scan
    EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
                  '.sh', '.bash', '.zsh', '.yml', '.yaml', '.json', '.xml', '.toml', 
                  '.ini', '.cfg', '.conf', '.env', '.properties', '.tf', '.tfvars'}
    ALWAYS_SCAN = {'.env', '.npmrc', '.pypirc', '.netrc', 'credentials', 'secrets'}
    SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'vendor', 
                 'target', 'build', 'dist', '.idea', '.vscode'}
    SKIP_FILES = {'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock', 
                  'go.sum', 'composer.lock'}
    
    def redact(secret, show=4):
        if len(secret) <= show * 2:
            return '*' * len(secret)
        return secret[:show] + '*' * (len(secret) - show * 2) + secret[-show:]
    
    findings = []
    files_scanned = 0
    errors = []
    
    scan_path = Path(path)
    
    if scan_path.is_file():
        files_to_scan = [scan_path]
    else:
        if recursive and not no_recursive:
            files_to_scan = scan_path.rglob('*')
        else:
            files_to_scan = scan_path.glob('*')
    
    for file_path in files_to_scan:
        if not file_path.is_file():
            continue
        if any(skip in file_path.parts for skip in SKIP_DIRS):
            continue
        if file_path.name in SKIP_FILES:
            continue
        
        should_scan = (file_path.suffix.lower() in EXTENSIONS or
                       file_path.name in ALWAYS_SCAN or
                       any(n in file_path.name.lower() for n in ALWAYS_SCAN))
        if not should_scan:
            continue
        
        files_scanned += 1
        if verbose:
            click.echo(f"Scanning: {file_path}", err=True)
        
        try:
            content = file_path.read_text(errors='ignore')
            for line_num, line in enumerate(content.splitlines(), 1):
                for name, (pattern, confidence) in PATTERNS.items():
                    if not include_low and confidence == 'low':
                        continue
                    for match in pattern.finditer(line):
                        findings.append({
                            'file': str(file_path),
                            'line': line_num,
                            'type': name,
                            'match': redact(match.group()),
                            'confidence': confidence,
                            'content': line.strip()[:100],
                        })
        except Exception as e:
            errors.append(f"{file_path}: {e}")
    
    # Build result
    result = {
        'files_scanned': files_scanned,
        'files_with_secrets': len(set(f['file'] for f in findings)),
        'total_findings': len(findings),
        'findings': findings,
        'errors': errors,
    }
    
    if json_output:
        click.echo(json.dumps(result, indent=2))
        if findings:
            sys.exit(1)
        return
    
    if quiet and not findings:
        sys.exit(0)
    
    if not quiet:
        click.echo(f"\n{'=' * 60}")
        click.echo(f"  Secret Scan Results")
        click.echo(f"{'=' * 60}")
        click.echo(f"  Path: {path}")
        click.echo(f"  Files scanned: {files_scanned}")
        click.echo(f"  Files with secrets: {result['files_with_secrets']}")
        click.echo(f"  Total findings: {len(findings)}")
    
    if findings:
        if not quiet:
            click.echo(f"\n🔴 SECRETS DETECTED:\n")
        
        # Group by file
        by_file = {}
        for f in findings:
            by_file.setdefault(f['file'], []).append(f)
        
        for file_path, file_findings in by_file.items():
            try:
                rel = Path(file_path).relative_to(Path.cwd())
            except ValueError:
                rel = file_path
            click.echo(f"  📁 {rel}")
            for f in file_findings:
                conf_marker = '🔴' if f['confidence'] == 'high' else ('🟡' if f['confidence'] == 'medium' else '⚪')
                click.echo(f"    {conf_marker} Line {f['line']}: [{f['confidence'].upper()}] {f['type']}")
                click.echo(f"       Match: {f['match']}")
            click.echo()
        
        if not quiet:
            click.echo(f"{'=' * 60}")
            click.echo(f"⚠️  {len(findings)} secret(s) detected! Review before committing.")
        
        sys.exit(1)
    else:
        if not quiet:
            click.echo(f"\n✅ No secrets found")
            click.echo(f"{'=' * 60}")

@file_group.command('hash-check')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('-a', '--algorithm', default='sha256',
              type=click.Choice(['md5', 'sha1', 'sha256', 'sha512'], case_sensitive=False),
              help='Hash algorithm to use')
@click.option('-c', '--compare', help='Expected hash value to compare against')
def hash_check(file_path, algorithm, compare):
    """Calculate file hash for integrity verification

    Examples:
        bsot file hash-check /path/to/file
        bsot file hash-check file.zip --algorithm sha512
        bsot file hash-check download.iso --compare abc123def456...
    """
    try:
        # Select hash algorithm
        hash_func = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }[algorithm.lower()]()

        # Calculate hash
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)

        file_hash = hash_func.hexdigest()

        click.echo(f"File: {file_path}")
        click.echo(f"Algorithm: {algorithm.upper()}")
        click.echo(f"Hash: {file_hash}")

        if compare:
            if file_hash.lower() == compare.lower():
                click.echo("✅ Hash matches expected value")
            else:
                click.echo("❌ Hash does NOT match expected value")
                click.echo(f"Expected: {compare}")
                click.echo(f"Got:      {file_hash}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
