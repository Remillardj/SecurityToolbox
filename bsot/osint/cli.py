"""
CLI commands for the OSINT module.
Open Source Intelligence tools for investigating domains, emails, usernames, and more.

Note: Most commands in this module are scaffolded for future implementation.
"""

import click
from ..utils import Colors


def _not_implemented_panel(title: str, target: str, features: list):
    """Display a styled 'not implemented' message."""
    click.echo()
    click.echo(f"{Colors.YELLOW}{'═' * 60}{Colors.RESET}")
    click.echo(f"{Colors.YELLOW}  🚧 {title}{Colors.RESET}")
    click.echo(f"{Colors.YELLOW}{'═' * 60}{Colors.RESET}")
    click.echo()
    click.echo(f"  {Colors.BRIGHT_BLACK}Target: {target}{Colors.RESET}")
    click.echo()
    click.echo("  This command will include:")
    for feature in features:
        click.echo(f"  • {feature}")
    click.echo()
    click.echo(f"  {Colors.BRIGHT_BLACK}Coming soon in a future BSOT release.{Colors.RESET}")
    click.echo()


@click.group()
def osint():
    """
    Open Source Intelligence (OSINT) tools.
    
    Investigate domains, emails, usernames, and more using
    publicly available data sources.
    
    \b
    Commands:
      domain      Domain reconnaissance (WHOIS, DNS, subdomains)
      email       Email investigation and breach lookup
      username    Username enumeration across platforms
      person      Person search across public sources
      image       Image EXIF extraction and reverse search
      metadata    File metadata extraction
      company     Company/org intelligence gathering
      phone       Phone number lookup and validation
      dork        Google dorking query generator
      pastebin    Paste site search
      archive     Wayback Machine lookup
    
    \b
    Examples:
      bsot osint domain example.com
      bsot osint email user@example.com --breaches
      bsot osint username johndoe
    
    Note: Most commands in this module are not yet implemented.
    They are scaffolded for future development.
    """
    pass


# ============================================================================
# Domain Reconnaissance
# ============================================================================

@osint.command()
@click.argument('domain')
@click.option('--deep', is_flag=True, help='Also enumerate subdomains from CT logs')
@click.option('--resolve', is_flag=True, help='With --deep, resolve each subdomain')
@click.option('--timeout', default=30, show_default=True, help='Per-lookup timeout in seconds')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def domain(domain, deep, resolve, timeout, json_output):
    """
    Domain reconnaissance: WHOIS, DNS, email security, and SSL.

    \b
    Composes the WHOIS, DNS and SSL checks into one passive profile. Add
    --deep to enumerate subdomains from Certificate Transparency logs.

    \b
    Examples:
        bsot osint domain example.com
        bsot osint domain example.com --deep
        bsot osint domain example.com --json
    """
    import json as json_lib
    import re
    import socket
    import sys
    from ..utils import print_header, print_subheader

    domain = domain.strip().lower().lstrip('*.')
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$', domain):
        click.echo(f"Error: '{domain}' is not a valid domain", err=True)
        sys.exit(2)

    profile = {'domain': domain, 'errors': {}}

    # --- WHOIS ---------------------------------------------------------
    try:
        from ..intel.whois_client import WhoisClient
        whois_result = WhoisClient().lookup(domain)
        profile['whois'] = (
            whois_result.to_dict() if hasattr(whois_result, 'to_dict') else whois_result
        )
    except ImportError:
        profile['errors']['whois'] = 'python-whois not installed (pip install "bsot[full]")'
    except Exception as e:
        profile['errors']['whois'] = str(e)

    # --- DNS + email authentication ------------------------------------
    try:
        from ..network.dns_security import DNSChecker
        dns_result = DNSChecker().check(domain)
        profile['dns'] = dns_result.to_dict() if hasattr(dns_result, 'to_dict') else dns_result
    except ImportError:
        profile['errors']['dns'] = 'dnspython not installed'
    except Exception as e:
        profile['errors']['dns'] = str(e)

    # --- SSL certificate -----------------------------------------------
    try:
        from ..network.ssl_checker import SSLChecker
        ssl_result = SSLChecker().check(domain, 443)
        profile['ssl'] = ssl_result.to_dict() if hasattr(ssl_result, 'to_dict') else ssl_result
    except Exception as e:
        profile['errors']['ssl'] = str(e)

    # --- Subdomains (opt-in; hits crt.sh) -------------------------------
    if deep:
        try:
            import requests
            response = requests.get(
                'https://crt.sh/',
                params={'q': f'%.{domain}', 'output': 'json'},
                timeout=timeout,
                headers={'User-Agent': 'bsot/osint-domain'},
            )
            if response.status_code == 200:
                names = set()
                for rec in response.json():
                    for name in (rec.get('name_value') or '').split('\n'):
                        name = name.strip().lower().lstrip('*.')
                        if name.endswith(domain):
                            names.add(name)
                subdomains = []
                for name in sorted(names):
                    entry = {'name': name}
                    if resolve:
                        try:
                            entry['addresses'] = sorted({
                                info[4][0] for info in socket.getaddrinfo(name, None)
                            })
                        except (socket.gaierror, OSError):
                            entry['addresses'] = []
                        entry['live'] = bool(entry['addresses'])
                    subdomains.append(entry)
                profile['subdomains'] = subdomains
            else:
                profile['errors']['subdomains'] = f'crt.sh returned HTTP {response.status_code}'
        except Exception as e:
            profile['errors']['subdomains'] = str(e)

    if json_output:
        click.echo(json_lib.dumps(profile, indent=2, default=str))
        return

    print_header(f"OSINT Domain Profile: {domain}")

    whois_data = profile.get('whois') or {}
    if whois_data:
        print_subheader('Registration')
        for label, key in (
            ('Registrar', 'registrar'),
            ('Created', 'creation_date'),
            ('Expires', 'expiration_date'),
            ('Registrant', 'registrant'),
        ):
            value = whois_data.get(key)
            if value:
                click.echo(f"  {label}: {value}")

    dns_data = profile.get('dns') or {}
    records = dns_data.get('records') or {}
    if records or dns_data.get('email_security_grade'):
        print_subheader('DNS')
        for label, key in (('A', 'a'), ('AAAA', 'aaaa'), ('MX', 'mx'), ('NS', 'ns')):
            values = records.get(key) or []
            if values:
                rendered = ', '.join(
                    v if isinstance(v, str) else str(v.get('host', v)) for v in values[:4]
                )
                click.echo(f"  {label}: {rendered}")
        email_security = dns_data.get('email_security') or {}
        for mech in ('spf', 'dmarc', 'dkim'):
            entry = email_security.get(mech)
            if isinstance(entry, dict) and entry.get('found') is not None:
                state = 'present' if entry.get('found') else 'missing'
                click.echo(f"  {mech.upper()}: {state}")
        grade = dns_data.get('email_security_grade')
        if grade:
            click.echo(f"  Email security grade: {grade}")

    ssl_data = profile.get('ssl') or {}
    certificate = ssl_data.get('certificate') or {}
    if certificate and not ssl_data.get('error'):
        print_subheader('SSL')
        click.echo(f"  Issuer: {(certificate.get('issuer') or {}).get('common_name', 'N/A')}")
        click.echo(f"  Expires: {certificate.get('not_after', 'N/A')}"
                   f" ({certificate.get('days_until_expiry', '?')} days)")
        grade = (ssl_data.get('security') or {}).get('grade')
        if grade:
            click.echo(f"  Grade: {grade}")

    if 'subdomains' in profile:
        subs = profile['subdomains']
        print_subheader(f"Subdomains ({len(subs)})")
        for entry in subs[:40]:
            line = f"  {entry['name']}"
            if resolve and entry.get('live'):
                line += f" → {', '.join(entry['addresses'][:2])}"
            elif resolve:
                line += "  (no DNS)"
            click.echo(line)
        if len(subs) > 40:
            click.echo(f"  ... and {len(subs) - 40} more")

    if profile['errors']:
        print_subheader('Unavailable')
        for source, message in profile['errors'].items():
            click.echo(f"  {source}: {message}")

    click.echo()
