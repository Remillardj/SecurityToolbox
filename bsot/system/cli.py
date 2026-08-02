"""
CLI commands for the system monitoring module.
"""

import click
import sys
import json as json_lib


@click.group()
def system():
    """System monitoring tools."""
    pass


@system.command()
@click.option('--suspicious', '-s', is_flag=True, help='Only show suspicious processes')
@click.option('--vt', 'use_vt', is_flag=True,
              help='Look up each process binary hash on VirusTotal (needs an API key)')
@click.option('--vt-all', is_flag=True,
              help='With --vt, check every process rather than only suspicious ones')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def processes(suspicious, use_vt, vt_all, json_output):
    """
    List and analyze running processes.
    
    Detects suspicious indicators:
    - Known malicious process names
    - Processes running from temp directories
    - Deleted binaries
    - Hidden processes
    
    \b
    Examples:
        bsot system processes
        bsot system processes --suspicious
        bsot system processes --json
    """
    from .processes import ProcessAnalyzer
    from ..utils import Colors, print_header, print_subheader
    
    analyzer = ProcessAnalyzer()
    
    if not analyzer.psutil:
        click.echo("Error: psutil library not installed. Install with: pip install psutil", err=True)
        sys.exit(2)
    
    procs = analyzer.list_processes(suspicious_only=suspicious)

    vt_findings = {}
    if use_vt:
        vt_findings = _vt_check_processes(procs, check_all=vt_all)

    if json_output:
        payload = []
        for proc in procs:
            entry = proc.to_dict()
            if proc.exe in vt_findings:
                entry['virustotal'] = vt_findings[proc.exe]
            payload.append(entry)
        click.echo(json_lib.dumps(payload, indent=2))
        return
    
    print_header("Running Processes")
    click.echo(f"  Total: {len(procs)}")
    
    # Sort by CPU usage
    procs.sort(key=lambda x: x.cpu_percent, reverse=True)
    
    # Show suspicious first
    suspicious_procs = [p for p in procs if p.is_suspicious]
    if suspicious_procs:
        print_subheader(f"Suspicious Processes ({len(suspicious_procs)})")
        for proc in suspicious_procs:
            click.echo(f"\n  {Colors.RED}[!]{Colors.RESET} PID {proc.pid}: {proc.name}")
            click.echo(f"      User: {proc.username}")
            click.echo(f"      Path: {proc.exe[:60]}..." if len(proc.exe) > 60 else f"      Path: {proc.exe}")
            for reason in proc.suspicious_reasons:
                click.echo(f"      {Colors.RED}• {reason}{Colors.RESET}")
            _echo_vt_verdict(vt_findings.get(proc.exe), Colors)
    
    # Show top processes by CPU
    print_subheader("Top Processes by CPU")
    click.echo(f"\n  {'PID':>6}  {'CPU%':>5}  {'MEM%':>5}  {'USER':<12}  {'NAME':<20}")
    click.echo("  " + "-" * 60)
    
    for proc in procs[:20]:
        indicator = f"{Colors.RED}!{Colors.RESET}" if proc.is_suspicious else " "
        click.echo(f"  {proc.pid:>6}  {proc.cpu_percent:>5.1f}  {proc.memory_percent:>5.1f}  "
                  f"{proc.username[:12]:<12}  {indicator}{proc.name[:20]}")
    
    if len(procs) > 20:
        click.echo(f"\n  ... and {len(procs) - 20} more processes")
    
    click.echo()
    
    if suspicious_procs:
        sys.exit(1)


@system.command()
@click.option('--suspicious', '-s', is_flag=True, help='Only show suspicious connections')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def connections(suspicious, json_output):
    """
    Show active network connections.
    
    Note: May require root/admin privileges on some systems.
    
    \b
    Examples:
        bsot system connections
        bsot system connections --suspicious
    """
    from .processes import ProcessAnalyzer
    from ..utils import print_header
    
    analyzer = ProcessAnalyzer()
    
    if not analyzer.psutil:
        click.echo("Error: psutil library not installed. Install with: pip install psutil", err=True)
        sys.exit(2)
    
    try:
        conns = analyzer.get_network_connections()
    except analyzer.psutil.AccessDenied:
        click.echo("Error: Permission denied. Try running with sudo/admin privileges.", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    
    # Filter for established connections
    established = [c for c in conns if c['status'] == 'ESTABLISHED']
    
    if json_output:
        click.echo(json_lib.dumps(established, indent=2))
        return
    
    print_header("Network Connections")
    click.echo(f"  Established: {len(established)}")
    
    click.echo(f"\n  {'LOCAL':<22}  {'REMOTE':<22}  {'PID':>6}  {'PROCESS':<15}")
    click.echo("  " + "-" * 70)
    
    for conn in established[:30]:
        proc = conn.get('process', {})
        proc_name = proc.get('name', 'unknown')[:15]
        proc_pid = proc.get('pid', '-')
        
        click.echo(f"  {conn['local']:<22}  {conn['remote']:<22}  {proc_pid:>6}  {proc_name}")
    
    if len(established) > 30:
        click.echo(f"\n  ... and {len(established) - 30} more connections")
    
    click.echo()



@system.command()
@click.option('--user', 'user_only', is_flag=True, help='Only per-user locations (no system paths)')
@click.option('--suspicious-only', is_flag=True, help='Only entries matching suspicious heuristics')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def persistence(user_only, suspicious_only, json_output):
    """
    Enumerate persistence mechanisms on this host.

    \b
    Covers launch agents/daemons and cron on macOS, systemd units and cron on
    Linux. Entries are flagged when they run from world-writable or
    user-writable paths, reference interpreters, or hide in temp directories.

    \b
    Examples:
        bsot system persistence
        bsot system persistence --suspicious-only
        bsot system persistence --json
    """
    import os
    import platform
    import re
    import stat as stat_mod
    from pathlib import Path
    from ..utils import Colors, print_header, print_subheader

    system_name = platform.system()
    entries = []

    # Paths that should not host a legitimate autostart payload.
    SUSPECT_DIRS = ('/tmp', '/var/tmp', '/private/tmp', '/dev/shm', '/Users/Shared')
    # Matched against argv[0]'s basename only. Substring matching here produces
    # nonsense ("ionodecache" contains "node", "SourceSync" contains "nc").
    INTERPRETERS = frozenset({
        'python', 'python2', 'python3', 'perl', 'ruby', 'bash', 'sh', 'zsh',
        'dash', 'ksh', 'osascript', 'curl', 'wget', 'nc', 'ncat', 'netcat',
        'powershell', 'pwsh', 'node', 'php', 'env',
    })

    def inspect(path: Path, kind: str, payload: str = ''):
        """Build an entry, applying suspicion heuristics."""
        reasons = []
        try:
            st = path.stat()
            if st.st_mode & stat_mod.S_IWOTH:
                reasons.append('world-writable definition')
        except OSError:
            st = None

        blob = f"{payload} {path}"

        # Temp-dir references: match a real path component, not a substring.
        for d in SUSPECT_DIRS:
            if re.search(rf'(?<![\w/]){re.escape(d)}/', blob):
                reasons.append(f'references {d}')
                break

        # Interpreters: inspect the basename of the invoked executable only.
        argv0 = payload.strip().split()[0] if payload.strip() else ''
        exe = os.path.basename(argv0).lower()
        if exe in INTERPRETERS:
            reasons.append(f'invokes {exe}')

        # Pipe-to-shell and encoded-payload patterns anywhere in the command.
        if re.search(r'\|\s*(?:ba|z|k)?sh\b', blob):
            reasons.append('pipes into a shell')
        if re.search(r'\bbase64\s+(?:-d|--decode)\b|\b-[eE]ncodedCommand\b', blob):
            reasons.append('decodes an encoded payload')
        if re.search(r'\bcurl\b[^|]*\|', blob) or re.search(r'\bwget\b[^|]*\|', blob):
            reasons.append('downloads and executes')

        if path.name.startswith('.'):
            reasons.append('hidden file')

        entries.append({
            'type': kind,
            'path': str(path),
            'payload': payload.strip()[:300],
            'suspicious': bool(reasons),
            'reasons': reasons,
        })

    def read_plist(path: Path) -> str:
        """Extract ProgramArguments/Program from a plist, binary or XML."""
        try:
            import plistlib
            with open(path, 'rb') as f:
                data = plistlib.load(f)
            args = data.get('ProgramArguments') or []
            program = data.get('Program', '')
            return ' '.join([program] + [str(a) for a in args]).strip()
        except Exception:
            try:
                return path.read_text(errors='replace')[:300]
            except OSError:
                return ''

    home = Path.home()

    if system_name == 'Darwin':
        launch_dirs = [
            (home / 'Library/LaunchAgents', 'launch-agent (user)'),
            (Path('/Library/LaunchAgents'), 'launch-agent (system)'),
            (Path('/Library/LaunchDaemons'), 'launch-daemon'),
        ]
        if not user_only:
            launch_dirs += [
                (Path('/System/Library/LaunchAgents'), 'launch-agent (apple)'),
                (Path('/System/Library/LaunchDaemons'), 'launch-daemon (apple)'),
            ]
        for d, kind in launch_dirs:
            if user_only and 'user' not in kind:
                continue
            if not d.is_dir():
                continue
            for item in sorted(d.glob('*.plist')):
                inspect(item, kind, read_plist(item))

    elif system_name == 'Linux':
        unit_dirs = [
            (home / '.config/systemd/user', 'systemd (user)'),
        ]
        if not user_only:
            unit_dirs += [
                (Path('/etc/systemd/system'), 'systemd (system)'),
                (Path('/usr/lib/systemd/system'), 'systemd (vendor)'),
                (Path('/etc/init.d'), 'init.d'),
            ]
        for d, kind in unit_dirs:
            if not d.is_dir():
                continue
            for item in sorted(d.glob('*')):
                if item.is_file():
                    try:
                        text = item.read_text(errors='replace')
                    except OSError:
                        text = ''
                    exec_line = ' '.join(
                        line.split('=', 1)[1].strip()
                        for line in text.splitlines()
                        if line.strip().startswith('ExecStart')
                    )
                    inspect(item, kind, exec_line or text[:200])

        for rc in ('/etc/rc.local',):
            p = Path(rc)
            if p.is_file() and not user_only:
                try:
                    inspect(p, 'rc.local', p.read_text(errors='replace')[:300])
                except OSError:
                    pass

    # cron: user crontab plus system cron directories
    try:
        import subprocess
        out = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    cron_reasons = []
                    # Skip the 5 schedule fields; the command follows.
                    cmd = ' '.join(line.split()[5:]) if len(line.split()) > 5 else line
                    cron_exe = os.path.basename(cmd.split()[0]).lower() if cmd.split() else ''
                    if cron_exe in INTERPRETERS:
                        cron_reasons.append(f'invokes {cron_exe}')
                    for d in SUSPECT_DIRS:
                        if re.search(rf'(?<![\w/]){re.escape(d)}/', line):
                            cron_reasons.append(f'references {d}')
                            break
                    if re.search(r'\|\s*(?:ba|z|k)?sh\b', line):
                        cron_reasons.append('pipes into a shell')
                    entries.append({
                        'type': 'crontab (user)',
                        'path': 'crontab -l',
                        'payload': line[:300],
                        'suspicious': bool(cron_reasons),
                        'reasons': cron_reasons,
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    if not user_only:
        for cron_dir in ('/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/periodic'):
            d = Path(cron_dir)
            if not d.is_dir():
                continue
            for item in sorted(d.rglob('*')):
                if item.is_file():
                    try:
                        payload = item.read_text(errors='replace')[:200]
                    except OSError:
                        payload = ''
                    inspect(item, 'cron', payload)

    shown = [e for e in entries if e['suspicious']] if suspicious_only else entries
    suspicious_count = sum(1 for e in entries if e['suspicious'])

    if json_output:
        click.echo(json_lib.dumps({
            'platform': system_name,
            'total': len(entries),
            'suspicious': suspicious_count,
            'entries': shown,
        }, indent=2))
    else:
        print_header(f"Persistence Mechanisms ({system_name})")
        if not shown:
            click.echo(f"  {Colors.GREEN}Nothing found{Colors.RESET}\n")
        else:
            by_type = {}
            for e in shown:
                by_type.setdefault(e['type'], []).append(e)
            for kind, items in sorted(by_type.items()):
                print_subheader(f"{kind} ({len(items)})")
                for e in items:
                    marker = f"{Colors.RED}⚠{Colors.RESET} " if e['suspicious'] else "  "
                    click.echo(f"  {marker}{e['path']}")
                    if e['payload']:
                        click.echo(f"      {Colors.DIM}{e['payload'][:160]}{Colors.RESET}")
                    for r in e['reasons']:
                        click.echo(f"      {Colors.YELLOW}→ {r}{Colors.RESET}")
            click.echo()
            click.echo(f"  {len(entries)} mechanism(s); {suspicious_count} flagged.")
            click.echo()

    if suspicious_count:
        sys.exit(1)


def _vt_check_processes(procs, check_all: bool = False) -> dict:
    """
    Hash each process binary and look the hashes up on VirusTotal.

    Returns a mapping of executable path to a VT summary. Only suspicious
    processes are checked by default: VirusTotal's public API allows 4 lookups
    per minute, so scanning every process would take many minutes.
    """
    import hashlib
    from ..config import config as global_config
    from ..utils import Colors

    api_key = global_config.virustotal_api_key
    if not api_key:
        click.echo(
            f"{Colors.YELLOW}Warning: no VirusTotal API key configured; "
            f"skipping VT lookups. Set VIRUSTOTAL_API_KEY or run "
            f"'bsot config set virustotal_api_key <key>'.{Colors.RESET}",
            err=True,
        )
        return {}

    from ..intel.sources.virustotal import VirusTotalClient

    client = VirusTotalClient(api_key)
    targets = [p for p in procs if p.exe and (check_all or p.is_suspicious)]

    # Deduplicate by path: many processes share one binary.
    unique_paths = []
    seen = set()
    for proc in targets:
        if proc.exe not in seen:
            seen.add(proc.exe)
            unique_paths.append(proc.exe)

    if not unique_paths:
        return {}

    if len(unique_paths) > 4:
        click.echo(
            f"{Colors.DIM}Checking {len(unique_paths)} binaries against VirusTotal "
            f"(public API allows 4/minute, so this may take a while)...{Colors.RESET}",
            err=True,
        )

    findings = {}
    for path in unique_paths:
        try:
            digest = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    digest.update(chunk)
            file_hash = digest.hexdigest()
        except (OSError, PermissionError) as e:
            findings[path] = {'error': f'could not hash: {e}'}
            continue

        try:
            result = client.lookup_hash(file_hash)
        except Exception as e:
            findings[path] = {'sha256': file_hash, 'error': str(e)}
            continue

        if result is None:
            findings[path] = {'sha256': file_hash, 'found': False}
            continue

        findings[path] = {
            'sha256': file_hash,
            'found': True,
            'malicious': result.malicious,
            'suspicious': result.suspicious,
            'detection_ratio': result.detection_ratio,
            'is_malicious': result.is_malicious,
        }

    return findings


def _echo_vt_verdict(verdict: dict, Colors) -> None:
    """Print a one-line VirusTotal verdict beneath a process entry."""
    if not verdict:
        return
    if verdict.get('error'):
        click.echo(f"      {Colors.DIM}VT: {verdict['error']}{Colors.RESET}")
    elif not verdict.get('found'):
        # An unknown hash is itself notable for a binary running on a host.
        click.echo(f"      {Colors.YELLOW}VT: hash not in VirusTotal{Colors.RESET}")
    elif verdict.get('is_malicious'):
        click.echo(
            f"      {Colors.RED}{Colors.BOLD}VT: MALICIOUS "
            f"({verdict['detection_ratio']}){Colors.RESET}"
        )
    elif verdict.get('suspicious'):
        click.echo(f"      {Colors.YELLOW}VT: suspicious ({verdict['detection_ratio']}){Colors.RESET}")
    else:
        click.echo(f"      {Colors.GREEN}VT: clean ({verdict['detection_ratio']}){Colors.RESET}")
