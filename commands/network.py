#!/usr/bin/env python3
"""
Network security scanning and analysis commands
"""

import click
import socket
import ssl
import json
from datetime import datetime
from typing import Dict, List, Any
import subprocess
import re

@click.group('network')
def network_group():
    """Network security scanning and analysis tools"""
    pass

@network_group.command('ssl-check')
@click.argument('host')
@click.option('-p', '--port', default=443, help='Port to connect to (default: 443)')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed certificate information')
@click.option('-j', '--json', 'output_json', is_flag=True, help='Output as JSON')
@click.option('--check-expiry', is_flag=True, help='Only check certificate expiration')
def ssl_check(host, port, verbose, output_json, check_expiry):
    """Check SSL/TLS certificate and security configuration

    Examples:
        bsot network ssl-check google.com
        bsot network ssl-check example.com --port 8443
        bsot network ssl-check github.com --verbose
        bsot network ssl-check mysite.com --check-expiry
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()

        # Connect to the server
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse certificate information
                analysis = {
                    'host': host,
                    'port': port,
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'protocol': version,
                    'cipher': cipher,
                    'warnings': [],
                    'san': []
                }

                # Extract Subject Alternative Names
                if 'subjectAltName' in cert:
                    analysis['san'] = [name[1] for name in cert['subjectAltName']]

                # Check expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days

                analysis['days_until_expiry'] = days_until_expiry

                if days_until_expiry < 0:
                    analysis['warnings'].append('❌ Certificate has EXPIRED')
                elif days_until_expiry < 30:
                    analysis['warnings'].append(f'⚠️  Certificate expires in {days_until_expiry} days')
                elif days_until_expiry < 90:
                    analysis['warnings'].append(f'⚠️  Certificate expires soon ({days_until_expiry} days)')

                # Check for weak protocols
                if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                    analysis['warnings'].append(f'⚠️  Weak protocol in use: {version}')

                # Check for weak ciphers
                weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
                cipher_name = cipher[0] if cipher else ''
                if any(weak in cipher_name for weak in weak_ciphers):
                    analysis['warnings'].append(f'⚠️  Weak cipher detected: {cipher_name}')

                # Check key size
                if cipher and len(cipher) > 2:
                    key_bits = cipher[2]
                    if key_bits < 128:
                        analysis['warnings'].append(f'⚠️  Weak key size: {key_bits} bits')

                # Output results
                if output_json:
                    click.echo(json.dumps(analysis, indent=2, default=str))
                elif check_expiry:
                    if days_until_expiry < 0:
                        click.echo(f"❌ EXPIRED {abs(days_until_expiry)} days ago")
                    else:
                        click.echo(f"✅ Valid for {days_until_expiry} days (expires: {not_after.strftime('%Y-%m-%d')})")
                else:
                    click.echo("=" * 60)
                    click.echo("SSL/TLS CERTIFICATE CHECK")
                    click.echo("=" * 60)
                    click.echo(f"\nHost: {host}:{port}")
                    click.echo(f"Subject: {analysis['subject'].get('commonName', 'N/A')}")
                    click.echo(f"Issuer: {analysis['issuer'].get('commonName', 'N/A')}")
                    click.echo(f"Valid From: {cert['notBefore']}")
                    click.echo(f"Valid Until: {cert['notAfter']}")
                    click.echo(f"Days Until Expiry: {days_until_expiry}")
                    click.echo(f"\nProtocol: {version}")
                    click.echo(f"Cipher: {cipher[0] if cipher else 'N/A'}")
                    if cipher and len(cipher) > 2:
                        click.echo(f"Key Size: {cipher[2]} bits")

                    if analysis['san']:
                        click.echo(f"\nSubject Alternative Names:")
                        for san in analysis['san']:
                            click.echo(f"  - {san}")

                    if analysis['warnings']:
                        click.echo(f"\n⚠️  SECURITY WARNINGS:")
                        for warning in analysis['warnings']:
                            click.echo(f"  {warning}")
                    else:
                        click.echo(f"\n✅ No security issues detected")

                    if verbose:
                        click.echo(f"\nFULL CERTIFICATE:")
                        click.echo(json.dumps(analysis, indent=2, default=str))

    except socket.gaierror:
        click.echo(f"Error: Unable to resolve hostname '{host}'", err=True)
    except socket.timeout:
        click.echo(f"Error: Connection to {host}:{port} timed out", err=True)
    except ConnectionRefusedError:
        click.echo(f"Error: Connection to {host}:{port} refused", err=True)
    except ssl.SSLError as e:
        click.echo(f"Error: SSL/TLS error - {e}", err=True)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)

@network_group.command('port-scan')
@click.argument('host')
@click.option('-p', '--ports', default='1-1024', help='Port range to scan (e.g., 1-1024 or 80,443,8080)')
@click.option('-t', '--timeout', default=1, help='Connection timeout in seconds (default: 1)')
@click.option('-v', '--verbose', is_flag=True, help='Show closed ports as well')
def port_scan(host, ports, timeout, verbose):
    """Scan ports on a target host

    Examples:
        bsot network port-scan 192.168.1.1
        bsot network port-scan example.com --ports 80,443,8080
        bsot network port-scan 10.0.0.1 --ports 1-65535 --timeout 0.5
    """
    # Parse port specification
    port_list = []
    try:
        if ',' in ports:
            # Comma-separated list
            port_list = [int(p.strip()) for p in ports.split(',')]
        elif '-' in ports:
            # Range
            start, end = ports.split('-')
            port_list = list(range(int(start), int(end) + 1))
        else:
            # Single port
            port_list = [int(ports)]
    except ValueError:
        click.echo(f"Error: Invalid port specification '{ports}'", err=True)
        return

    click.echo(f"Scanning {host} for open ports...")
    click.echo(f"Port range: {ports}")
    click.echo(f"Total ports: {len(port_list)}")
    click.echo("=" * 60)

    open_ports = []
    common_services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }

    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                service = common_services.get(port, 'Unknown')
                click.echo(f"✅ Port {port:5d} - OPEN    [{service}]")
                open_ports.append((port, service))
            elif verbose:
                click.echo(f"❌ Port {port:5d} - CLOSED")

            sock.close()
        except socket.gaierror:
            click.echo(f"Error: Unable to resolve hostname '{host}'", err=True)
            return
        except KeyboardInterrupt:
            click.echo("\nScan interrupted by user")
            break
        except Exception as e:
            if verbose:
                click.echo(f"Error scanning port {port}: {e}", err=True)

    click.echo("=" * 60)
    click.echo(f"Scan complete: {len(open_ports)} open port(s) found")

@network_group.command('web-headers')
@click.argument('url')
@click.option('-v', '--verbose', is_flag=True, help='Show all headers')
@click.option('-j', '--json', 'output_json', is_flag=True, help='Output as JSON')
def web_headers(url, verbose, output_json):
    """Check HTTP security headers

    Examples:
        bsot network web-headers https://example.com
        bsot network web-headers https://github.com --verbose
    """
    try:
        import requests
    except ImportError:
        click.echo("Error: requests library not installed. Install with: pip install requests", err=True)
        return

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': 'HSTS - Forces HTTPS connections',
            'Content-Security-Policy': 'CSP - Prevents XSS and injection attacks',
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME-sniffing protection',
            'X-XSS-Protection': 'XSS filter (legacy)',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features',
        }

        analysis = {
            'url': url,
            'status_code': response.status_code,
            'final_url': response.url,
            'security_headers': {},
            'missing_headers': [],
            'warnings': [],
            'all_headers': dict(headers) if verbose else {}
        }

        # Check each security header
        for header, description in security_headers.items():
            if header in headers:
                analysis['security_headers'][header] = {
                    'value': headers[header],
                    'description': description
                }
            else:
                analysis['missing_headers'].append({
                    'header': header,
                    'description': description
                })

        # Check for insecure headers
        if 'Server' in headers:
            analysis['warnings'].append(f"Server header exposed: {headers['Server']}")

        if 'X-Powered-By' in headers:
            analysis['warnings'].append(f"X-Powered-By header exposed: {headers['X-Powered-By']}")

        if url.startswith('https://') and 'Strict-Transport-Security' not in headers:
            analysis['warnings'].append("Missing HSTS header on HTTPS site")

        # Output results
        if output_json:
            click.echo(json.dumps(analysis, indent=2))
        else:
            click.echo("=" * 60)
            click.echo("WEB SECURITY HEADERS CHECK")
            click.echo("=" * 60)
            click.echo(f"\nURL: {url}")
            click.echo(f"Status: {response.status_code}")
            if response.url != url:
                click.echo(f"Redirected to: {response.url}")

            if analysis['security_headers']:
                click.echo(f"\n✅ SECURITY HEADERS PRESENT:")
                for header, info in analysis['security_headers'].items():
                    click.echo(f"\n  {header}:")
                    click.echo(f"    Value: {info['value']}")
                    click.echo(f"    Purpose: {info['description']}")

            if analysis['missing_headers']:
                click.echo(f"\n⚠️  MISSING SECURITY HEADERS:")
                for missing in analysis['missing_headers']:
                    click.echo(f"  - {missing['header']}: {missing['description']}")

            if analysis['warnings']:
                click.echo(f"\n⚠️  WARNINGS:")
                for warning in analysis['warnings']:
                    click.echo(f"  - {warning}")

            if verbose and analysis['all_headers']:
                click.echo(f"\nALL HEADERS:")
                for header, value in analysis['all_headers'].items():
                    click.echo(f"  {header}: {value}")

    except requests.RequestException as e:
        click.echo(f"Error: Unable to fetch URL - {e}", err=True)

@network_group.command('dns-lookup')
@click.argument('domain')
@click.option('-t', '--type', 'record_type', default='ALL',
              help='DNS record type (A, AAAA, MX, TXT, NS, SOA, SPF, DMARC, ALL)')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed information')
@click.option('-j', '--json', 'output_json', is_flag=True, help='Output as JSON')
def dns_lookup(domain, record_type, verbose, output_json):
    """Perform DNS security lookup

    Examples:
        bsot network dns-lookup example.com
        bsot network dns-lookup google.com --type MX
        bsot network dns-lookup example.com --type SPF
    """
    try:
        import dns.resolver
    except ImportError:
        click.echo("Error: dnspython library not installed. Install with: pip install dnspython", err=True)
        return

    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA'] if record_type == 'ALL' else [record_type.upper()]

    analysis = {
        'domain': domain,
        'records': {},
        'security': {
            'spf': None,
            'dmarc': None,
            'dkim_selector': None
        },
        'warnings': []
    }

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            analysis['records'][rtype] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            analysis['records'][rtype] = []
        except dns.resolver.NXDOMAIN:
            analysis['warnings'].append(f"Domain {domain} does not exist")
            break
        except Exception as e:
            if verbose:
                analysis['warnings'].append(f"Error querying {rtype}: {e}")

    # Check for SPF record
    if 'TXT' in analysis['records']:
        for record in analysis['records']['TXT']:
            if 'v=spf1' in record:
                analysis['security']['spf'] = record
            if 'v=DMARC1' in record or 'v=dmarc1' in record:
                analysis['security']['dmarc'] = record

    # Check DMARC at _dmarc subdomain
    try:
        dmarc_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in dmarc_answers:
            record = str(rdata)
            if 'v=DMARC1' in record or 'v=dmarc1' in record:
                analysis['security']['dmarc'] = record
    except:
        pass

    # Security warnings
    if not analysis['security']['spf']:
        analysis['warnings'].append("No SPF record found - email spoofing possible")
    if not analysis['security']['dmarc']:
        analysis['warnings'].append("No DMARC record found - email authentication weak")

    # Output results
    if output_json:
        click.echo(json.dumps(analysis, indent=2))
    else:
        click.echo("=" * 60)
        click.echo("DNS SECURITY LOOKUP")
        click.echo("=" * 60)
        click.echo(f"\nDomain: {domain}")

        for rtype, records in analysis['records'].items():
            if records:
                click.echo(f"\n{rtype} Records:")
                for record in records:
                    click.echo(f"  - {record}")

        if analysis['security']['spf'] or analysis['security']['dmarc']:
            click.echo(f"\nEMAIL SECURITY:")
            if analysis['security']['spf']:
                click.echo(f"  SPF: {analysis['security']['spf']}")
            if analysis['security']['dmarc']:
                click.echo(f"  DMARC: {analysis['security']['dmarc']}")

        if analysis['warnings']:
            click.echo(f"\n⚠️  WARNINGS:")
            for warning in analysis['warnings']:
                click.echo(f"  - {warning}")
