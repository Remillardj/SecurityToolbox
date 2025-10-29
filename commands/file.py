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
@click.argument('directory')
@click.option('-e', '--extensions', default='py,js,json,yaml,yml,env,conf,config,sh,txt',
              help='File extensions to scan (comma-separated)')
@click.option('-v', '--verbose', is_flag=True, help='Show file being scanned')
@click.option('--context', default=2, help='Lines of context to show around matches')
def cred_scan(directory, extensions, verbose, context):
    """Scan files for hardcoded credentials and secrets

    Examples:
        bsot file cred-scan /path/to/project
        bsot file cred-scan . --extensions "py,js,env"
        bsot file cred-scan ./src --verbose --context 3
    """
    # Patterns for detecting secrets
    patterns = {
        'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'AWS Secret Key': re.compile(r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE),
        'Generic API Key': re.compile(r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.IGNORECASE),
        'Generic Secret': re.compile(r'secret\s*[=:]\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
        'Password': re.compile(r'password\s*[=:]\s*["\']([^"\']{4,})["\']', re.IGNORECASE),
        'Private Key': re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----'),
        'JWT Token': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        'GitHub Token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        'Slack Token': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}'),
        'Google API Key': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
        'Database URL': re.compile(r'(mysql|postgres|mongodb)://[^:]+:[^@]+@[^/]+', re.IGNORECASE),
        'Generic Token': re.compile(r'token\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.IGNORECASE),
    }

    ext_list = [e.strip() for e in extensions.split(',')]
    findings = []

    click.echo(f"Scanning directory: {directory}")
    click.echo(f"File extensions: {', '.join(ext_list)}")
    click.echo("=" * 60)

    for root, _, files in os.walk(directory):
        for file in files:
            # Check file extension
            file_ext = file.split('.')[-1] if '.' in file else ''
            if file_ext not in ext_list:
                continue

            file_path = os.path.join(root, file)

            if verbose:
                click.echo(f"Scanning: {file_path}")

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line_num, line in enumerate(lines, 1):
                    for pattern_name, pattern in patterns.items():
                        matches = pattern.finditer(line)
                        for match in matches:
                            # Get context lines
                            start_line = max(0, line_num - context - 1)
                            end_line = min(len(lines), line_num + context)
                            context_lines = lines[start_line:end_line]

                            findings.append({
                                'file': file_path,
                                'line': line_num,
                                'pattern': pattern_name,
                                'match': match.group(0)[:50],  # Truncate for display
                                'context': context_lines,
                                'context_start': start_line + 1
                            })
            except (PermissionError, FileNotFoundError, UnicodeDecodeError) as e:
                if verbose:
                    click.echo(f"Error reading {file_path}: {e}", err=True)

    # Display findings
    if findings:
        click.echo(f"\n🔴 POTENTIAL SECRETS FOUND ({len(findings)}):\n")
        for finding in findings:
            click.echo(f"📁 {finding['file']}:{finding['line']}")
            click.echo(f"🔍 Pattern: {finding['pattern']}")
            click.echo(f"🔑 Match: {finding['match']}...")
            click.echo(f"\nContext:")
            for i, ctx_line in enumerate(finding['context']):
                line_no = finding['context_start'] + i
                prefix = ">>>" if line_no == finding['line'] else "   "
                click.echo(f"  {prefix} {line_no:4d} | {ctx_line.rstrip()}")
            click.echo()
    else:
        click.echo("✅ No hardcoded credentials found")

    click.echo("=" * 60)
    click.echo(f"Scan complete: {len(findings)} potential secret(s) found")

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
