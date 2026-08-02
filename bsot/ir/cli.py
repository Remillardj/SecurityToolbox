"""
CLI commands for the incident response module.
"""

import click
import sys
import json as json_lib


@click.group()
def ir():
    """Incident response and forensics tools."""
    pass


@ir.command()
@click.option('--profile', '-p', type=click.Choice(['quick', 'standard', 'full']),
              default='standard', help='Collection profile')
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory')
@click.option('--json', 'json_output', is_flag=True, help='JSON manifest output')
def collect(profile, output_dir, json_output):
    """
    Collect forensic artifacts from the system.
    
    Profiles:
    - quick: Processes, network, users (~30 seconds)
    - standard: + scheduled tasks, startup items, recent files
    - full: + installed software, all user accounts
    
    \b
    Examples:
        bsot ir collect
        bsot ir collect --profile full -o ./evidence
    """
    from .collector import ArtifactCollector
    from ..utils import Colors, print_header, print_subheader
    
    if not json_output:
        print_header("Forensic Artifact Collection")
        click.echo(f"  Profile: {profile}")
        click.echo(f"  Hostname: {click.get_current_context().obj}")
        click.echo("\n  Collecting artifacts...")
    
    collector = ArtifactCollector(output_dir=output_dir)
    manifest = collector.collect(profile=profile)
    
    if json_output:
        click.echo(json_lib.dumps(manifest.to_dict(), indent=2))
        return
    
    click.echo(f"\n  {Colors.GREEN}✓ Collection complete{Colors.RESET}")
    click.echo(f"\n  Output directory: {collector.output_dir}")
    click.echo(f"  Files collected: {manifest.total_files}")
    click.echo(f"  Total size: {manifest.total_bytes / 1024:.1f} KB")
    
    print_subheader("Artifacts Collected")
    for artifact in manifest.artifacts:
        click.echo(f"  • {artifact['category']}/{artifact['name']}")
    
    if manifest.errors:
        print_subheader("Errors")
        for error in manifest.errors:
            click.echo(f"  ⚠️  {error}")
    
    click.echo()


@ir.command('hash-tree')
@click.argument('path', type=click.Path(exists=True))
@click.option('--algorithm', '-a', default='sha256', help='Hash algorithm')
@click.option('--output', '-o', type=click.Path(), help='Output manifest file')
@click.option('--json', 'json_output', is_flag=True, help='JSON output to stdout')
def hash_tree(path, algorithm, output, json_output):
    """
    Hash all files in a directory for evidence integrity.
    
    Creates a manifest with hashes that can be used to verify
    evidence integrity later.
    
    \b
    Examples:
        bsot ir hash-tree ./evidence
        bsot ir hash-tree ./evidence -o manifest.json
        bsot ir hash-tree ./evidence --json
    """
    from .collector import hash_directory
    from ..utils import Colors, print_header
    
    if not json_output:
        print_header(f"Hashing Directory: {path}")
        click.echo(f"  Algorithm: {algorithm}")
        click.echo("\n  Processing...")
    
    manifest = hash_directory(path, algorithm)
    
    if json_output:
        click.echo(json_lib.dumps(manifest, indent=2))
        return
    
    output_path = output or 'evidence_manifest.json'
    with open(output_path, 'w') as f:
        json_lib.dump(manifest, f, indent=2)
    
    click.echo(f"\n  {Colors.GREEN}✓ Complete{Colors.RESET}")
    click.echo(f"\n  Files hashed: {manifest['summary']['total_files']}")
    click.echo(f"  Total size: {manifest['summary']['total_bytes'] / 1024:.1f} KB")
    click.echo(f"  Root hash: {manifest['summary']['root_hash']}")
    click.echo(f"  Manifest: {output_path}")
    click.echo()


@ir.command()
@click.option('--block-ip', help='Generate command to block IP')
@click.option('--block-domain', help='Generate command to block domain')
@click.option('--disable-user', help='Generate command to disable user')
@click.option('--platform', type=click.Choice(['auto', 'linux', 'macos', 'windows']),
              default='auto', help='Target platform')
def contain(block_ip, block_domain, disable_user, platform):
    """
    Generate containment commands (does NOT execute them).
    
    Generates commands for blocking IPs, domains, or disabling users
    that you can review before executing manually.
    
    \b
    Examples:
        bsot ir contain --block-ip 1.2.3.4
        bsot ir contain --disable-user malicious_user
    """
    from ..utils import Colors, print_header, print_subheader
    import platform as plat
    
    if platform == 'auto':
        platform = plat.system().lower()
        if platform == 'darwin':
            platform = 'macos'
    
    print_header("Containment Commands")
    click.echo(f"  Platform: {platform}")
    click.echo(f"\n  {Colors.YELLOW}⚠️  These commands are for review only.{Colors.RESET}")
    click.echo(f"  {Colors.YELLOW}   Execute them manually after verification.{Colors.RESET}")
    
    if block_ip:
        print_subheader(f"Block IP: {block_ip}")
        
        if platform == 'linux':
            click.echo("\n  # Block IP with iptables")
            click.echo(f"  sudo iptables -A INPUT -s {block_ip} -j DROP")
            click.echo(f"  sudo iptables -A OUTPUT -d {block_ip} -j DROP")
            click.echo("\n  # Rollback:")
            click.echo(f"  sudo iptables -D INPUT -s {block_ip} -j DROP")
            click.echo(f"  sudo iptables -D OUTPUT -d {block_ip} -j DROP")
        
        elif platform == 'macos':
            click.echo("\n  # Block IP with pf")
            click.echo(f"  echo 'block drop from {block_ip}' | sudo pfctl -a 'bsot/block' -f -")
            click.echo("  sudo pfctl -e")
            click.echo("\n  # Rollback:")
            click.echo("  sudo pfctl -a 'bsot/block' -F all")
        
        elif platform == 'windows':
            click.echo("\n  # Block IP with Windows Firewall")
            click.echo(f"  netsh advfirewall firewall add rule name=\"BSOT Block {block_ip}\" dir=in action=block remoteip={block_ip}")
            click.echo(f"  netsh advfirewall firewall add rule name=\"BSOT Block {block_ip} Out\" dir=out action=block remoteip={block_ip}")
            click.echo("\n  # Rollback:")
            click.echo(f"  netsh advfirewall firewall delete rule name=\"BSOT Block {block_ip}\"")
            click.echo(f"  netsh advfirewall firewall delete rule name=\"BSOT Block {block_ip} Out\"")
    
    if disable_user:
        print_subheader(f"Disable User: {disable_user}")
        
        if platform == 'linux':
            click.echo("\n  # Disable user account")
            click.echo(f"  sudo usermod -L {disable_user}")
            click.echo(f"  sudo usermod -s /usr/sbin/nologin {disable_user}")
            click.echo("\n  # Kill user sessions")
            click.echo(f"  sudo pkill -u {disable_user}")
            click.echo("\n  # Rollback:")
            click.echo(f"  sudo usermod -U {disable_user}")
            click.echo(f"  sudo usermod -s /bin/bash {disable_user}")
        
        elif platform == 'macos':
            click.echo("\n  # Disable user account")
            click.echo(f"  sudo dscl . -create /Users/{disable_user} UserShell /usr/bin/false")
            click.echo("\n  # Kill user sessions")
            click.echo(f"  sudo pkill -u {disable_user}")
        
        elif platform == 'windows':
            click.echo("\n  # Disable user account")
            click.echo(f"  net user {disable_user} /active:no")
            click.echo("\n  # Rollback:")
            click.echo(f"  net user {disable_user} /active:yes")
    
    click.echo()


# ============================================================================
# Cloudflare Integration Commands
# ============================================================================

@ir.group('cf')
def cloudflare():
    """Cloudflare firewall management for incident response."""
    pass


@cloudflare.command('block')
@click.argument('ip')
@click.option('--note', '-n', default='Blocked via BSOT IR', help='Note to attach to the rule')
@click.option('--mode', type=click.Choice(['block', 'challenge', 'js_challenge', 'managed_challenge']),
              default='block', help='Block mode')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def cf_block(ip, note, mode, json_output):
    """
    Block an IP address on Cloudflare.
    
    Requires CLOUDFLARE_API_TOKEN and either CLOUDFLARE_ZONE_ID or 
    CLOUDFLARE_ACCOUNT_ID environment variables.
    
    \b
    Examples:
        bsot ir cf block 1.2.3.4
        bsot ir cf block 1.2.3.0/24 --note "Botnet range"
        bsot ir cf block 5.6.7.8 --mode challenge
    """
    from .cloudflare import CloudflareClient
    from ..config import config
    from ..utils import Colors, print_header
    
    api_token = config.cloudflare_api_token
    zone_id = config.cloudflare_zone_id
    account_id = config.cloudflare_account_id
    
    if not api_token:
        click.echo("Error: CLOUDFLARE_API_TOKEN not set", err=True)
        click.echo("Set via: export CLOUDFLARE_API_TOKEN=your_token", err=True)
        click.echo("Or: bsot config set cloudflare_api_token your_token", err=True)
        sys.exit(2)
    
    if not zone_id and not account_id:
        click.echo("Error: CLOUDFLARE_ZONE_ID or CLOUDFLARE_ACCOUNT_ID not set", err=True)
        sys.exit(2)
    
    try:
        client = CloudflareClient(api_token, zone_id=zone_id, account_id=account_id)
        result = client.block_ip(ip, notes=note, mode=mode)
        
        if json_output:
            click.echo(json_lib.dumps(result, indent=2))
        else:
            print_header("Cloudflare IP Block")
            click.echo(f"  {Colors.GREEN}✓ Successfully blocked {ip}{Colors.RESET}")
            click.echo(f"  Rule ID: {result['rule_id']}")
            click.echo(f"  Mode: {mode}")
            click.echo(f"\n  To unblock: bsot ir cf unblock {result['rule_id']}")
            click.echo()
            
    except Exception as e:
        if json_output:
            click.echo(json_lib.dumps({'success': False, 'error': str(e)}))
        else:
            click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cloudflare.command('unblock')
@click.argument('rule_id')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def cf_unblock(rule_id, json_output):
    """
    Remove an IP block rule from Cloudflare.
    
    \b
    Examples:
        bsot ir cf unblock abc123def456
    """
    from .cloudflare import CloudflareClient
    from ..config import config
    from ..utils import Colors, print_header
    
    api_token = config.cloudflare_api_token
    zone_id = config.cloudflare_zone_id
    account_id = config.cloudflare_account_id
    
    if not api_token:
        click.echo("Error: CLOUDFLARE_API_TOKEN not set", err=True)
        sys.exit(2)
    
    try:
        client = CloudflareClient(api_token, zone_id=zone_id, account_id=account_id)
        result = client.unblock_ip(rule_id)
        
        if json_output:
            click.echo(json_lib.dumps(result, indent=2))
        else:
            print_header("Cloudflare Rule Removed")
            click.echo(f"  {Colors.GREEN}✓ Successfully removed rule{Colors.RESET}")
            click.echo(f"  Rule ID: {rule_id}")
            click.echo()
            
    except Exception as e:
        if json_output:
            click.echo(json_lib.dumps({'success': False, 'error': str(e)}))
        else:
            click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cloudflare.command('list')
@click.option('--mode', type=click.Choice(['block', 'challenge', 'whitelist', 'js_challenge']),
              help='Filter by mode')
@click.option('--search', '-s', help='Search for IP or note')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def cf_list(mode, search, json_output):
    """
    List Cloudflare IP access rules.
    
    \b
    Examples:
        bsot ir cf list
        bsot ir cf list --mode block
        bsot ir cf list --search 1.2.3
    """
    from .cloudflare import CloudflareClient
    from ..config import config
    from ..utils import Colors, print_header
    
    api_token = config.cloudflare_api_token
    zone_id = config.cloudflare_zone_id
    account_id = config.cloudflare_account_id
    
    if not api_token:
        click.echo("Error: CLOUDFLARE_API_TOKEN not set", err=True)
        sys.exit(2)
    
    try:
        client = CloudflareClient(api_token, zone_id=zone_id, account_id=account_id)
        rules = client.list_rules(mode=mode, search=search)
        
        if json_output:
            click.echo(json_lib.dumps([r.to_dict() for r in rules], indent=2))
            return
        
        print_header("Cloudflare Access Rules")
        click.echo(f"  Total: {len(rules)}")
        
        if not rules:
            click.echo("\n  No rules found.")
        else:
            click.echo(f"\n  {'ID':<32}  {'MODE':<10}  {'VALUE':<20}  {'NOTES'}")
            click.echo("  " + "-" * 80)
            
            for rule in rules:
                mode_color = Colors.RED if rule.mode == 'block' else Colors.YELLOW
                click.echo(f"  {rule.id:<32}  {mode_color}{rule.mode:<10}{Colors.RESET}  "
                          f"{rule.value:<20}  {rule.notes[:30]}")
        
        click.echo()
            
    except Exception as e:
        if json_output:
            click.echo(json_lib.dumps({'success': False, 'error': str(e)}))
        else:
            click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cloudflare.command('bulk-block')
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='File with IPs (one per line)')
@click.option('--note', '-n', default='Blocked via BSOT IR', help='Note for all rules')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def cf_bulk_block(input_file, note, json_output):
    """
    Block multiple IPs from a file.
    
    \b
    Examples:
        bsot ir cf bulk-block -f malicious_ips.txt
        bsot ir cf bulk-block -f iocs.txt --note "Campaign X"
    """
    from .cloudflare import CloudflareClient
    from ..config import config
    from ..utils import Colors, print_header
    
    api_token = config.cloudflare_api_token
    zone_id = config.cloudflare_zone_id
    account_id = config.cloudflare_account_id
    
    if not api_token:
        click.echo("Error: CLOUDFLARE_API_TOKEN not set", err=True)
        sys.exit(2)
    
    # Read IPs from file
    with open(input_file, 'r') as f:
        ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not ips:
        click.echo("Error: No IPs found in file", err=True)
        sys.exit(2)
    
    try:
        client = CloudflareClient(api_token, zone_id=zone_id, account_id=account_id)
        
        if not json_output:
            print_header("Cloudflare Bulk Block")
            click.echo(f"  IPs to block: {len(ips)}")
            click.echo("  Processing...")
        
        results = client.bulk_block(ips, notes=note)
        
        if json_output:
            click.echo(json_lib.dumps(results, indent=2))
        else:
            click.echo(f"\n  {Colors.GREEN}✓ Blocked: {len(results['success'])}{Colors.RESET}")
            click.echo(f"  {Colors.YELLOW}⊘ Skipped: {len(results['skipped'])}{Colors.RESET}")
            click.echo(f"  {Colors.RED}✗ Failed: {len(results['failed'])}{Colors.RESET}")
            
            if results['failed']:
                click.echo("\n  Failed IPs:")
                for fail in results['failed'][:10]:
                    click.echo(f"    {fail['ip']}: {fail['error']}")
            
            click.echo()
            
    except Exception as e:
        if json_output:
            click.echo(json_lib.dumps({'success': False, 'error': str(e)}))
        else:
            click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cloudflare.command('test')
def cf_test():
    """
    Test Cloudflare API connection.
    
    \b
    Examples:
        bsot ir cf test
    """
    from .cloudflare import CloudflareClient
    from ..config import config
    from ..utils import Colors, print_header
    
    api_token = config.cloudflare_api_token
    zone_id = config.cloudflare_zone_id
    account_id = config.cloudflare_account_id
    
    print_header("Cloudflare Connection Test")
    
    if not api_token:
        click.echo(f"  {Colors.RED}✗ CLOUDFLARE_API_TOKEN not set{Colors.RESET}")
        sys.exit(2)
    else:
        click.echo(f"  {Colors.GREEN}✓ API token configured{Colors.RESET}")
    
    if zone_id:
        click.echo(f"  {Colors.GREEN}✓ Zone ID: {zone_id[:8]}...{Colors.RESET}")
    elif account_id:
        click.echo(f"  {Colors.GREEN}✓ Account ID: {account_id[:8]}...{Colors.RESET}")
    else:
        click.echo(f"  {Colors.RED}✗ No Zone ID or Account ID set{Colors.RESET}")
        sys.exit(2)
    
    try:
        client = CloudflareClient(api_token, zone_id=zone_id, account_id=account_id)
        result = client.test_connection()
        
        if result['success']:
            click.echo(f"\n  {Colors.GREEN}✓ API connection successful!{Colors.RESET}")
            click.echo(f"  Status: {result['status']}")
        else:
            click.echo(f"\n  {Colors.RED}✗ API connection failed{Colors.RESET}")
            click.echo(f"  Error: {result['message']}")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"\n  {Colors.RED}✗ Connection error: {e}{Colors.RESET}")
        sys.exit(1)
    
    click.echo()

