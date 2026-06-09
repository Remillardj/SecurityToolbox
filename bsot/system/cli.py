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
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def processes(suspicious, json_output):
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
    
    if json_output:
        click.echo(json_lib.dumps([p.to_dict() for p in procs], indent=2))
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
    from ..utils import Colors, print_header
    
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

