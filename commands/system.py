#!/usr/bin/env python3
"""
System security monitoring commands
"""

import click
import os
import subprocess
import hashlib
from pathlib import Path
import platform

@click.group('system')
def system_group():
    """System security monitoring tools"""
    pass

@system_group.command('process-check')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed information')
@click.option('--vt-api-key', envvar='VT_API_KEY', help='VirusTotal API key (or set VT_API_KEY env var)')
def process_check(verbose, vt_api_key):
    """Check for suspicious processes

    Examples:
        bsot system process-check
        bsot system process-check --verbose
        bsot system process-check --vt-api-key YOUR_API_KEY
    """
    import json
    import time

    VT_API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

    def calculate_checksum(filepath):
        """Calculate SHA-256 checksum of a file"""
        try:
            if not os.path.isfile(filepath):
                return None
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            return None

    def check_virustotal(checksum):
        """Check file hash against VirusTotal"""
        if not vt_api_key:
            return None

        try:
            import requests
            params = {'apikey': vt_api_key, 'resource': checksum}
            response = requests.get(VT_API_URL, params=params, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return result
            return None
        except Exception as e:
            if verbose:
                click.echo(f"Error checking VirusTotal: {e}", err=True)
            return None

    def get_process_path(pid):
        """Get the executable path for a process based on the OS"""
        system = platform.system()

        if system == 'Linux':
            try:
                return os.readlink(f'/proc/{pid}/exe')
            except (FileNotFoundError, PermissionError):
                return None
        elif system == 'Darwin':  # macOS
            try:
                cmd = ['lsof', '-p', str(pid), '-F', 'n']
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8')
                for line in output.splitlines():
                    if line.startswith('n'):
                        path = line[1:]
                        if path in ['/', '/dev/null', '/dev/zero'] or os.path.isdir(path):
                            continue
                        return path
            except (subprocess.SubprocessError, FileNotFoundError):
                return None
        return None

    def is_suspicious_process(process):
        """Check if a process is suspicious based on various criteria"""
        cmd = process.get('COMMAND', '')
        pid = process.get('PID', '')

        # Skip kernel processes and system processes
        system_processes = [
            'kernel_task', 'launchd', 'WindowServer', 'Finder',
            'systemd', 'init', 'kthreadd', 'ksoftirqd',
            'ps', 'lsof'
        ]

        if cmd.startswith('[') or any(sys_proc in cmd for sys_proc in system_processes):
            return False, None

        exe_path = get_process_path(pid)
        if exe_path is None or not os.path.isfile(exe_path):
            return False, None

        checksum = calculate_checksum(exe_path)
        if checksum is None:
            return False, None

        # Check VirusTotal
        if vt_api_key:
            vt_result = check_virustotal(checksum)
            if vt_result and vt_result.get('positives', 0) > 0:
                return True, {
                    'type': 'virustotal',
                    'details': f"Detected by {vt_result['positives']} antivirus engines",
                    'path': exe_path,
                    'checksum': checksum
                }

        # Check for suspicious indicators
        suspicious_indicators = [
            '/tmp/', '/var/tmp/',
            '/dev/shm/',
            '/private/var/folders/',
        ]

        if any(indicator in exe_path for indicator in suspicious_indicators):
            return True, {
                'type': 'suspicious_location',
                'details': f"Process running from suspicious location",
                'path': exe_path,
                'checksum': checksum
            }

        return False, None

    def get_processes():
        """Get process list based on the OS"""
        system = platform.system()

        if system in ['Linux', 'Darwin']:
            cmd = ['ps', 'aux']
        else:
            click.echo("Error: Unsupported operating system", err=True)
            return []

        try:
            output = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout.readlines()
            output = [line.decode('utf-8') for line in output]
            headers = [h for h in ' '.join(output[0].strip().split()).split() if h]
            raw_data = map(lambda s: s.strip().split(None, len(headers) - 1), output[1:])
            return [dict(zip(headers, r)) for r in raw_data]
        except Exception as e:
            click.echo(f"Error getting process list: {e}", err=True)
            return []

    # Main execution
    click.echo("Scanning for suspicious processes...")
    click.echo(f"Operating System: {platform.system()}")
    if not vt_api_key:
        click.echo("⚠️  No VirusTotal API key provided - skipping VT checks")
    click.echo("=" * 60)

    suspicious_found = False

    for process in get_processes():
        is_suspicious, details = is_suspicious_process(process)
        if is_suspicious:
            suspicious_found = True
            click.echo("\n🔴 SUSPICIOUS PROCESS DETECTED:")
            click.echo(f"  PID: {process.get('PID', 'N/A')}")
            click.echo(f"  User: {process.get('USER', 'N/A')}")
            click.echo(f"  Command: {process.get('COMMAND', 'N/A')}")
            click.echo(f"  CPU: {process.get('%CPU', 'N/A')}%")
            click.echo(f"  Memory: {process.get('%MEM', 'N/A')}%")
            if details:
                click.echo(f"  Reason: {details['type']}")
                click.echo(f"  Details: {details['details']}")
                click.echo(f"  Path: {details['path']}")
                click.echo(f"  SHA-256: {details['checksum']}")
            click.echo("-" * 60)

    if not suspicious_found:
        click.echo("✅ No suspicious processes detected")
