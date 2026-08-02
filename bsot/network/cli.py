"""
CLI commands for the network security module.
"""

import click
import sys
import json as json_lib
import socket
import time


@click.group()
def network():
    """Network security analysis tools."""
    pass


@network.command('ssl-check')
@click.argument('host')
@click.option('--port', '-p', default=443, help='Port (default: 443)')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def ssl_check(host, port, json_output):
    """
    Comprehensive SSL/TLS certificate analysis.
    
    Checks certificate validity, expiration, protocol version, cipher strength.
    
    \b
    Examples:
        bsot network ssl-check google.com
        bsot network ssl-check example.com:8443
        bsot network ssl-check myserver.com --json
    """
    from .ssl_checker import SSLChecker
    from ..utils import Colors, print_header, print_subheader, print_finding
    
    # Parse host:port
    if ':' in host:
        host, port = host.rsplit(':', 1)
        port = int(port)
    
    checker = SSLChecker()
    result = checker.check(host, port)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header(f"SSL/TLS Check: {host}:{port}")
    
    if result.error:
        click.echo(f"\n  {Colors.RED}❌ Error: {result.error}{Colors.RESET}")
        sys.exit(2)
    
    # Grade
    grade_colors = {'A': Colors.GREEN, 'B': Colors.GREEN, 'C': Colors.YELLOW, 'D': Colors.YELLOW, 'F': Colors.RED}
    grade_color = grade_colors.get(result.grade, Colors.WHITE)
    click.echo(f"\n  {grade_color}{Colors.BOLD}Grade: {result.grade}{Colors.RESET}")
    
    # Certificate info
    print_subheader("Certificate")
    click.echo(f"  Subject: {result.cert_subject.get('common_name', 'N/A')}")
    click.echo(f"  Issuer: {result.cert_issuer.get('common_name', 'N/A')}")
    click.echo(f"  Valid From: {result.not_before}")
    click.echo(f"  Valid Until: {result.not_after}")
    
    if result.is_expired:
        print_finding('high', 'Certificate is EXPIRED!')
    elif result.is_expiring_soon:
        print_finding('medium', f'Certificate expires in {result.days_until_expiry} days')
    else:
        click.echo(f"  {Colors.GREEN}✓ Expires in {result.days_until_expiry} days{Colors.RESET}")
    
    # SANs
    if result.san:
        click.echo(f"\n  Alternative Names: {', '.join(result.san[:5])}")
        if len(result.san) > 5:
            click.echo(f"    ... and {len(result.san) - 5} more")
    
    # Protocol
    print_subheader("Protocol & Cipher")
    click.echo(f"  Protocol: {result.protocol_version}")
    click.echo(f"  Cipher: {result.cipher_name}")
    click.echo(f"  Key Size: {result.cipher_bits} bits")
    
    # Warnings
    if result.warnings:
        print_subheader("Warnings")
        for warning in result.warnings:
            click.echo(f"  ⚠️  {warning}")
    
    # Vulnerabilities
    if result.vulnerabilities:
        print_subheader("Vulnerabilities")
        for vuln in result.vulnerabilities:
            print_finding('high', vuln)
    
    click.echo()
    
    # Exit code
    if result.grade == 'F' or result.is_expired:
        sys.exit(1)


@network.command()
@click.argument('url')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def headers(url, json_output):
    """
    Audit HTTP security headers.
    
    Checks HSTS, CSP, X-Frame-Options, and other security headers.
    
    \b
    Examples:
        bsot network headers https://example.com
        bsot network headers example.com --json
    """
    from .header_auditor import SecurityHeaderAuditor
    from ..utils import Colors, print_header, print_subheader
    
    auditor = SecurityHeaderAuditor()
    result = auditor.audit(url)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header(f"Security Headers: {result.url}")
    
    if result.error:
        click.echo(f"\n  {Colors.RED}❌ Error: {result.error}{Colors.RESET}")
        sys.exit(2)
    
    # Grade
    grade_colors = {'A': Colors.GREEN, 'B': Colors.GREEN, 'C': Colors.YELLOW, 'D': Colors.YELLOW, 'F': Colors.RED}
    grade_color = grade_colors.get(result.grade, Colors.WHITE)
    click.echo(f"\n  {grade_color}{Colors.BOLD}Grade: {result.grade} ({result.score}/100){Colors.RESET}")
    click.echo(f"  Status: {result.status_code}")
    
    # Header status
    print_subheader("Security Headers")
    for header, status in result.security_headers.items():
        if status['present']:
            if status['valid']:
                icon = f"{Colors.GREEN}✓{Colors.RESET}"
            else:
                icon = f"{Colors.YELLOW}!{Colors.RESET}"
            click.echo(f"  {icon} {header}")
            click.echo(f"      {status['value'][:60]}{'...' if len(status['value']) > 60 else ''}")
        else:
            importance = status['importance']
            if importance == 'critical':
                icon = f"{Colors.RED}✗{Colors.RESET}"
            elif importance == 'high':
                icon = f"{Colors.RED}✗{Colors.RESET}"
            elif importance == 'medium':
                icon = f"{Colors.YELLOW}✗{Colors.RESET}"
            else:
                icon = f"{Colors.BLUE}✗{Colors.RESET}"
            click.echo(f"  {icon} {header} (missing)")
    
    # Warnings
    if result.warnings:
        print_subheader("Warnings")
        for warning in result.warnings:
            click.echo(f"  ⚠️  {warning}")
    
    # Recommendations
    if result.recommendations:
        print_subheader("Recommendations")
        for rec in result.recommendations[:5]:
            click.echo(f"  • {rec}")
    
    click.echo()
    
    if result.grade in ('D', 'F'):
        sys.exit(1)


@network.command()
@click.argument('domain')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def dns(domain, json_output):
    """
    DNS security analysis including SPF, DKIM, DMARC.
    
    \b
    Examples:
        bsot network dns example.com
        bsot network dns google.com --json
    """
    from .dns_security import DNSChecker
    from ..utils import Colors, print_header, print_subheader
    
    checker = DNSChecker()
    result = checker.check(domain)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header(f"DNS Security: {domain}")
    
    if result.error:
        click.echo(f"\n  {Colors.RED}❌ Error: {result.error}{Colors.RESET}")
        sys.exit(2)
    
    # Email security grade
    grade_colors = {'A': Colors.GREEN, 'B': Colors.GREEN, 'C': Colors.YELLOW, 'D': Colors.YELLOW, 'F': Colors.RED}
    grade_color = grade_colors.get(result.email_security_grade, Colors.WHITE)
    click.echo(f"\n  {grade_color}{Colors.BOLD}Email Security Grade: {result.email_security_grade}{Colors.RESET}")
    
    # Basic records
    print_subheader("DNS Records")
    if result.a_records:
        click.echo(f"  A: {', '.join(result.a_records)}")
    if result.aaaa_records:
        click.echo(f"  AAAA: {', '.join(result.aaaa_records)}")
    if result.mx_records:
        click.echo(f"  MX: {', '.join(f'{r['priority']} {r['host']}' for r in result.mx_records[:3])}")
    if result.ns_records:
        click.echo(f"  NS: {', '.join(result.ns_records[:3])}")
    
    # Email security
    print_subheader("Email Authentication")
    
    # SPF
    if result.spf_valid:
        click.echo(f"  {Colors.GREEN}✓{Colors.RESET} SPF: {result.spf_policy}")
        click.echo(f"    {result.spf_record[:70]}...")
    else:
        click.echo(f"  {Colors.RED}✗{Colors.RESET} SPF: Not configured")
    
    # DMARC
    if result.dmarc_valid:
        click.echo(f"  {Colors.GREEN}✓{Colors.RESET} DMARC: {result.dmarc_policy}")
        click.echo(f"    {result.dmarc_record[:70]}...")
    else:
        click.echo(f"  {Colors.RED}✗{Colors.RESET} DMARC: Not configured")
    
    # DKIM
    if result.dkim_found:
        click.echo(f"  {Colors.GREEN}✓{Colors.RESET} DKIM: Found ({', '.join(result.dkim_selectors)})")
    else:
        click.echo(f"  {Colors.YELLOW}?{Colors.RESET} DKIM: Not found with common selectors")
    
    # DNSSEC
    print_subheader("Security")
    if result.dnssec:
        click.echo(f"  {Colors.GREEN}✓{Colors.RESET} DNSSEC: Enabled")
    else:
        click.echo(f"  {Colors.YELLOW}✗{Colors.RESET} DNSSEC: Not enabled")
    
    if result.caa_records:
        click.echo(f"  {Colors.GREEN}✓{Colors.RESET} CAA: {', '.join(result.caa_records[:2])}")
    
    # Warnings
    if result.warnings:
        print_subheader("Warnings")
        for warning in result.warnings:
            click.echo(f"  ⚠️  {warning}")
    
    # Recommendations
    if result.recommendations:
        print_subheader("Recommendations")
        for rec in result.recommendations:
            click.echo(f"  • {rec}")
    
    click.echo()


@network.command()
@click.argument('host')
@click.option('--ports', '-p', default='common',
              help='Ports: "22,80,443" or "1-1000" or "common"')
@click.option('--timeout', '-t', default=1000, help='Timeout per port in ms')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def ports(host, ports, timeout, json_output):
    """
    Scan for open ports.
    
    \b
    Examples:
        bsot network ports example.com
        bsot network ports 192.168.1.1 --ports 1-1000
        bsot network ports server.local --ports 22,80,443,8080
    """
    from ..utils import Colors, print_header
    
    # Common ports
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    
    # Parse ports
    if ports == 'common':
        port_list = COMMON_PORTS
    elif '-' in ports:
        start, end = ports.split('-')
        port_list = list(range(int(start), int(end) + 1))
    else:
        port_list = [int(p.strip()) for p in ports.split(',')]
    
    timeout_sec = timeout / 1000
    
    if not json_output:
        print_header(f"Port Scan: {host}")
        click.echo(f"  Scanning {len(port_list)} ports...")
    
    # Scan ports
    open_ports = []
    
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Port is open
                service = _guess_service(port)
                open_ports.append({'port': port, 'service': service, 'state': 'open'})
                
                if not json_output:
                    click.echo(f"  {Colors.GREEN}✓{Colors.RESET} {port:5} - {service}")
        except socket.gaierror:
            if not json_output:
                click.echo(f"  {Colors.RED}✗{Colors.RESET} Could not resolve host")
            break
        except Exception:
            pass
    
    if json_output:
        click.echo(json_lib.dumps({
            'host': host,
            'ports_scanned': len(port_list),
            'open_ports': open_ports
        }, indent=2))
    else:
        click.echo(f"\n  Found {len(open_ports)} open ports")


def _guess_service(port: int) -> str:
    """Guess service name from port number."""
    services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'MSRPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
    }
    return services.get(port, 'unknown')



@network.command('ct-subdomains')
@click.argument('domain')
@click.option('--include-expired', is_flag=True, help='Include certificates that have expired')
@click.option('--resolve', is_flag=True, help='Resolve each subdomain to check which are live')
@click.option('--timeout', default=30, show_default=True, help='HTTP timeout in seconds')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def ct_subdomains(domain, include_expired, resolve, timeout, json_output):
    """
    Enumerate subdomains from Certificate Transparency logs (crt.sh).

    \b
    Passive reconnaissance: queries public CT logs rather than touching the
    target, so it is safe to run against third-party infrastructure.

    \b
    Examples:
        bsot network ct-subdomains example.com
        bsot network ct-subdomains example.com --resolve
        bsot network ct-subdomains example.com --json
    """
    import re
    import requests
    from datetime import datetime, timezone
    from ..utils import Colors, print_header

    domain = domain.strip().lower().lstrip('*.')
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$', domain):
        click.echo(f"Error: '{domain}' is not a valid domain", err=True)
        sys.exit(2)

    # crt.sh frequently returns 502/503 under load, so transient failures are
    # retried rather than surfaced as a hard error on the first attempt.
    records = None
    last_error = None
    for attempt in range(3):
        try:
            response = requests.get(
                'https://crt.sh/',
                params={'q': f'%.{domain}', 'output': 'json'},
                timeout=timeout,
                headers={'User-Agent': 'bsot/ct-subdomains'},
            )
            if response.status_code in (429, 500, 502, 503, 504):
                last_error = f"HTTP {response.status_code}"
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                click.echo(
                    f"Error: crt.sh is unavailable ({last_error}) after 3 attempts. "
                    f"The service is often overloaded; try again shortly.",
                    err=True,
                )
                sys.exit(2)
            response.raise_for_status()
            records = response.json()
            break
        except requests.exceptions.Timeout:
            last_error = f"timed out after {timeout}s"
            if attempt < 2:
                continue
            click.echo(f"Error: crt.sh {last_error}", err=True)
            sys.exit(2)
        except requests.exceptions.RequestException as e:
            click.echo(f"Error: crt.sh request failed: {e}", err=True)
            sys.exit(2)
        except ValueError:
            # An HTML error page instead of JSON is another overload symptom.
            last_error = "non-JSON response"
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            click.echo("Error: crt.sh returned a non-JSON response", err=True)
            sys.exit(2)

    if records is None:
        click.echo(f"Error: crt.sh request failed ({last_error})", err=True)
        sys.exit(2)

    now = datetime.now(timezone.utc)
    subdomains = {}

    for rec in records:
        # name_value holds one or more names, newline-separated.
        for name in (rec.get('name_value') or '').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if not name or not name.endswith(domain):
                continue

            not_after = rec.get('not_after', '')
            expired = False
            if not_after:
                try:
                    expiry = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    expired = expiry < now
                except ValueError:
                    pass

            if expired and not include_expired:
                continue

            entry = subdomains.setdefault(name, {
                'name': name,
                'first_seen': rec.get('not_before', ''),
                'last_seen': rec.get('not_after', ''),
                'issuers': set(),
                'expired': expired,
            })
            entry['issuers'].add(rec.get('issuer_name', '')[:80])
            if not expired:
                entry['expired'] = False
            if rec.get('not_after', '') > entry['last_seen']:
                entry['last_seen'] = rec.get('not_after', '')

    results = []
    for name in sorted(subdomains):
        entry = subdomains[name]
        entry['issuers'] = sorted(i for i in entry['issuers'] if i)
        if resolve:
            try:
                entry['addresses'] = sorted({
                    info[4][0] for info in socket.getaddrinfo(name, None)
                })
            except (socket.gaierror, OSError):
                entry['addresses'] = []
            entry['live'] = bool(entry['addresses'])
        results.append(entry)

    if json_output:
        click.echo(json_lib.dumps({
            'domain': domain,
            'count': len(results),
            'subdomains': results,
        }, indent=2))
    else:
        print_header(f"CT Subdomains: {domain}")
        if not results:
            click.echo(f"  {Colors.YELLOW}No subdomains found in CT logs{Colors.RESET}\n")
        else:
            for entry in results:
                line = f"  {Colors.CYAN}{entry['name']}{Colors.RESET}"
                if entry['expired']:
                    line += f" {Colors.DIM}(cert expired){Colors.RESET}"
                if resolve:
                    if entry['live']:
                        line += f" {Colors.GREEN}→ {', '.join(entry['addresses'][:3])}{Colors.RESET}"
                    else:
                        line += f" {Colors.DIM}(no DNS){Colors.RESET}"
                click.echo(line)
            click.echo()
            live_note = ''
            if resolve:
                live_note = f"; {sum(1 for r in results if r['live'])} resolving"
            click.echo(f"  {len(results)} unique subdomain(s){live_note}.")
            click.echo()
