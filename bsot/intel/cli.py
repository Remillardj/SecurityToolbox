"""
CLI commands for the intel (threat intelligence) module.
"""

import click
import sys
import json as json_lib
from pathlib import Path


@click.group()
def intel():
    """Threat intelligence lookups and IOC enrichment."""
    pass


@intel.command()
@click.argument('ioc')
@click.option('--sources', '-s', default='all',
              help='Comma-separated sources: vt,abuseipdb,greynoise,otx,ipinfo or "all"')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--output', '-o', type=click.Path(), help='Write results to file')
@click.option('--no-cache', is_flag=True, help='Skip cache')
@click.pass_context
def enrich(ctx, ioc, sources, json_output, output, no_cache):
    """
    Enrich a single IOC against multiple threat intelligence sources.
    
    Auto-detects IOC type (IP, domain, URL, hash) and queries appropriate sources.
    
    \b
    Examples:
        bsot intel enrich 1.2.3.4
        bsot intel enrich evil.com --sources vt,otx
        bsot intel enrich abc123def456... --json
    """
    from .enricher import IOCEnricher
    from .ioc_utils import detect_ioc_type, defang
    from ..utils import Colors, print_header, print_subheader, print_finding, print_kv
    
    # Parse sources
    source_list = None
    if sources.lower() != 'all':
        source_list = [s.strip() for s in sources.split(',')]
    
    # Get cache setting from context
    use_cache = not (no_cache or ctx.obj.get('no_cache', False))
    
    enricher = IOCEnricher(use_cache=use_cache)
    
    # Check if any sources are available
    available = enricher.get_available_sources()
    if not available:
        click.echo("❌ No API keys configured. Set environment variables or use ~/.bsot/config.json", err=True)
        click.echo("\nRequired keys: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, GREYNOISE_API_KEY, OTX_API_KEY", err=True)
        sys.exit(2)
    
    # Detect IOC type
    ioc_type = detect_ioc_type(ioc)
    
    if not json_output:
        click.echo(f"\n🔍 Enriching {ioc_type.value}: {defang(ioc)}")
        click.echo(f"   Sources: {', '.join(available)}\n")
    
    # Enrich
    result = enricher.enrich(ioc, sources=source_list)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
    else:
        # Display results
        print_header("Enrichment Results")
        
        # Verdict
        verdict_colors = {
            'malicious': Colors.RED + Colors.BOLD,
            'suspicious': Colors.YELLOW + Colors.BOLD,
            'clean': Colors.GREEN + Colors.BOLD,
            'unknown': Colors.WHITE,
        }
        color = verdict_colors.get(result.verdict, Colors.WHITE)
        
        click.echo(f"  {color}▌ VERDICT: {result.verdict.upper()}{Colors.RESET}")
        click.echo(f"  {color}▌ CONFIDENCE: {int(result.confidence * 100)}%{Colors.RESET}")
        click.echo()
        
        # Summary
        click.echo(f"  📊 Sources: {result.malicious_count} malicious, "
                  f"{result.suspicious_count} suspicious, {result.clean_count} clean")
        
        if result.country:
            click.echo(f"  🌍 Country: {result.country}")
        if result.asn:
            click.echo(f"  🏢 ASN: {result.asn}")
        
        # Tags
        if result.tags:
            click.echo(f"\n  🏷️  Tags: {', '.join(result.tags[:10])}")
        
        if result.malware_families:
            click.echo(f"  🦠 Malware: {', '.join(result.malware_families[:5])}")
        
        # Source details
        print_subheader("Source Details")
        for source, data in result.sources.items():
            if not data:
                continue
            
            is_mal = data.get('is_malicious', False)
            is_sus = data.get('is_suspicious', False)
            
            if is_mal:
                status = f"{Colors.RED}MALICIOUS{Colors.RESET}"
            elif is_sus:
                status = f"{Colors.YELLOW}SUSPICIOUS{Colors.RESET}"
            else:
                status = f"{Colors.GREEN}CLEAN{Colors.RESET}"
            
            click.echo(f"\n  {Colors.CYAN}{source.upper()}{Colors.RESET}: {status}")
            
            # Source-specific details
            if source == 'virustotal':
                click.echo(f"    Detection: {data.get('detection_ratio', 'N/A')}")
                if data.get('link'):
                    click.echo(f"    Link: {data['link']}")
            
            elif source == 'abuseipdb':
                click.echo(f"    Abuse Score: {data.get('abuse_score', 0)}%")
                click.echo(f"    Reports: {data.get('total_reports', 0)}")
            
            elif source == 'greynoise':
                click.echo(f"    Classification: {data.get('classification', 'unknown')}")
                if data.get('noise'):
                    click.echo(f"    Noise: Yes (internet background noise)")
                if data.get('riot'):
                    click.echo(f"    RIOT: Yes (known good service)")
                if data.get('actor'):
                    click.echo(f"    Actor: {data['actor']}")
            
            elif source == 'otx':
                click.echo(f"    Pulses: {data.get('pulse_count', 0)}")
                if data.get('adversaries'):
                    click.echo(f"    Adversaries: {', '.join(data['adversaries'][:3])}")
            
            elif source == 'ipinfo':
                click.echo(f"    Location: {data.get('city', '')}, {data.get('country_name', '')}")
                click.echo(f"    Org: {data.get('org', 'N/A')}")
                flags = []
                if data.get('is_vpn'):
                    flags.append('VPN')
                if data.get('is_proxy'):
                    flags.append('Proxy')
                if data.get('is_tor'):
                    flags.append('Tor')
                if data.get('is_datacenter'):
                    flags.append('Datacenter')
                if flags:
                    click.echo(f"    Flags: {', '.join(flags)}")
        
        # Errors
        if result.errors:
            print_subheader("Errors")
            for error in result.errors:
                click.echo(f"  ⚠️  {error}")
        
        click.echo()
    
    # Export if requested
    if output:
        with open(output, 'w') as f:
            json_lib.dump(result.to_dict(), f, indent=2)
        if not json_output:
            click.echo(f"📄 Results saved to: {output}")
    
    # Exit code
    if result.verdict == 'malicious':
        sys.exit(1)
    sys.exit(0)


@intel.command()
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='File with IOCs (one per line)')
@click.option('--sources', '-s', default='all',
              help='Comma-separated sources or "all"')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--csv', 'csv_output', is_flag=True, help='CSV output')
@click.option('--output', '-o', type=click.Path(), help='Output file')
@click.option('--max-concurrent', default=5, help='Parallel requests (default: 5)')
@click.option('--progress', is_flag=True, help='Show progress bar')
def bulk(input_file, sources, json_output, csv_output, output, max_concurrent, progress):
    """
    Bulk IOC enrichment from file.
    
    \b
    Examples:
        bsot intel bulk -f iocs.txt
        bsot intel bulk -f iocs.txt --csv -o results.csv
        bsot intel bulk -f iocs.txt --progress
    """
    from .enricher import IOCEnricher
    
    # Read IOCs
    iocs = []
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                iocs.append(line)
    
    if not iocs:
        click.echo("No IOCs found in file", err=True)
        sys.exit(2)
    
    click.echo(f"📋 Loaded {len(iocs)} IOCs from {input_file}")
    
    # Parse sources
    source_list = None
    if sources.lower() != 'all':
        source_list = [s.strip() for s in sources.split(',')]
    
    enricher = IOCEnricher()
    results = enricher.enrich_bulk(iocs, sources=source_list, max_concurrent=max_concurrent, show_progress=progress)
    
    # Output
    if json_output:
        output_data = [r.to_dict() for r in results]
        click.echo(json_lib.dumps(output_data, indent=2))
    elif csv_output:
        # Generate CSV
        import csv
        import io
        
        output_io = io.StringIO()
        writer = csv.writer(output_io)
        writer.writerow(['ioc', 'type', 'verdict', 'confidence', 'malicious', 'suspicious', 'clean', 'tags'])
        
        for r in results:
            writer.writerow([
                r.ioc, r.ioc_type, r.verdict, r.confidence,
                r.malicious_count, r.suspicious_count, r.clean_count,
                ';'.join(r.tags[:5])
            ])
        
        csv_data = output_io.getvalue()
        
        if output:
            with open(output, 'w') as f:
                f.write(csv_data)
            click.echo(f"📄 Results saved to: {output}")
        else:
            click.echo(csv_data)
    else:
        # Summary output
        from ..utils import Colors
        
        malicious = [r for r in results if r.verdict == 'malicious']
        suspicious = [r for r in results if r.verdict == 'suspicious']
        clean = [r for r in results if r.verdict == 'clean']
        
        click.echo(f"\n📊 Results Summary:")
        click.echo(f"  {Colors.RED}Malicious: {len(malicious)}{Colors.RESET}")
        click.echo(f"  {Colors.YELLOW}Suspicious: {len(suspicious)}{Colors.RESET}")
        click.echo(f"  {Colors.GREEN}Clean: {len(clean)}{Colors.RESET}")
        click.echo(f"  Unknown: {len(results) - len(malicious) - len(suspicious) - len(clean)}")
        
        if malicious:
            click.echo(f"\n{Colors.RED}🚨 Malicious IOCs:{Colors.RESET}")
            for r in malicious[:10]:
                click.echo(f"  • {r.ioc} ({r.ioc_type})")
            if len(malicious) > 10:
                click.echo(f"  ... and {len(malicious) - 10} more")
        
        if output:
            output_data = [r.to_dict() for r in results]
            with open(output, 'w') as f:
                json_lib.dump(output_data, f, indent=2)
            click.echo(f"\n📄 Full results saved to: {output}")


@intel.command()
@click.argument('domain')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def whois(domain, json_output):
    """
    WHOIS lookup for domain registration information.
    
    \b
    Examples:
        bsot intel whois example.com
        bsot intel whois evil-phishing-site.xyz --json
    """
    from .whois_client import WHOISClient
    from ..utils import Colors, print_header, print_subheader, print_finding
    
    client = WHOISClient()
    result = client.lookup(domain)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header(f"WHOIS: {result.domain}")
    
    if result.error:
        click.echo(f"  ❌ Error: {result.error}")
        sys.exit(2)
    
    if not result.found:
        click.echo("  Domain not found")
        sys.exit(0)
    
    # Registrar
    print_subheader("Registrar")
    click.echo(f"  {result.registrar or 'Unknown'}")
    
    # Dates
    print_subheader("Dates")
    click.echo(f"  Created:  {result.creation_date or 'Unknown'}")
    click.echo(f"  Expires:  {result.expiration_date or 'Unknown'}")
    click.echo(f"  Updated:  {result.updated_date or 'Unknown'}")
    
    if result.domain_age_days:
        click.echo(f"  Age:      {result.domain_age_days} days")
    
    if result.days_until_expiration:
        click.echo(f"  Expires in: {result.days_until_expiration} days")
    
    # Warnings
    if result.is_newly_registered:
        print_finding('high', f'Domain is only {result.domain_age_days} days old - may be suspicious')
    
    if result.is_expiring_soon:
        print_finding('medium', f'Domain expires in {result.days_until_expiration} days')
    
    # Nameservers
    if result.nameservers:
        print_subheader("Nameservers")
        for ns in result.nameservers:
            click.echo(f"  • {ns}")
    
    # Registrant
    if result.registrant_org or result.registrant_country:
        print_subheader("Registrant")
        if result.registrant_org:
            click.echo(f"  Org: {result.registrant_org}")
        if result.registrant_country:
            click.echo(f"  Country: {result.registrant_country}")
    
    if result.privacy_protected:
        click.echo(f"\n  🔒 WHOIS Privacy Protection: Enabled")
    
    # Check suspicious characteristics
    flags = client.is_suspicious_domain(result)
    if flags['is_suspicious']:
        print_subheader("Suspicious Indicators")
        for reason in flags['reasons']:
            print_finding('medium', reason)
    
    click.echo()


@intel.command()
@click.argument('ip')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def geoip(ip, json_output):
    """
    IP geolocation and network context.
    
    \b
    Examples:
        bsot intel geoip 8.8.8.8
        bsot intel geoip 1.2.3.4 --json
    """
    from .sources.ipinfo import IPInfoClient
    from ..config import config
    from ..utils import Colors, print_header, print_subheader
    
    client = IPInfoClient(config.ipinfo_api_key)
    result = client.lookup(ip)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header(f"GeoIP: {ip}")
    
    if result.error:
        click.echo(f"  ❌ Error: {result.error}")
        sys.exit(2)
    
    # Location
    print_subheader("Location")
    click.echo(f"  Country: {result.country_name} ({result.country})")
    if result.region:
        click.echo(f"  Region:  {result.region}")
    if result.city:
        click.echo(f"  City:    {result.city}")
    if result.loc:
        click.echo(f"  Coords:  {result.loc}")
    if result.timezone:
        click.echo(f"  Timezone: {result.timezone}")
    
    # Network
    print_subheader("Network")
    click.echo(f"  Org: {result.org or 'Unknown'}")
    if result.asn:
        click.echo(f"  ASN: {result.asn}")
    if result.hostname:
        click.echo(f"  Hostname: {result.hostname}")
    
    # Flags
    flags = []
    if result.is_vpn:
        flags.append(f"{Colors.YELLOW}VPN{Colors.RESET}")
    if result.is_proxy:
        flags.append(f"{Colors.YELLOW}Proxy{Colors.RESET}")
    if result.is_tor:
        flags.append(f"{Colors.RED}Tor{Colors.RESET}")
    if result.is_datacenter:
        flags.append("Datacenter")
    if result.is_bogon:
        flags.append("Bogon")
    
    if flags:
        print_subheader("Classification")
        click.echo(f"  {', '.join(flags)}")
    
    click.echo()


@intel.command()
@click.argument('ioc')
def defang(ioc):
    """
    Defang an IOC for safe sharing.
    
    \b
    Examples:
        bsot intel defang https://evil.com/malware
        bsot intel defang 1.2.3.4
        echo "evil.com" | bsot intel defang -
    """
    from .ioc_utils import defang as do_defang
    
    if ioc == '-':
        # Read from stdin
        import sys
        ioc = sys.stdin.read().strip()
    
    click.echo(do_defang(ioc))


@intel.command()
@click.argument('ioc')
def refang(ioc):
    """
    Refang a defanged IOC back to original form.
    
    \b
    Examples:
        bsot intel refang "hxxps://evil[.]com"
        bsot intel refang "1[.]2[.]3[.]4"
    """
    from .ioc_utils import refang as do_refang
    
    if ioc == '-':
        import sys
        ioc = sys.stdin.read().strip()
    
    click.echo(do_refang(ioc))


@intel.command()
@click.argument('query')
@click.option('--limit', '-n', default=10, help='Max results (default: 10)')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--verbose', '-v', is_flag=True, help='Show full descriptions')
@click.option('--minimal', '-m', is_flag=True, help='Minimal output (CVE ID, score, severity only)')
def cve(query, limit, json_output, verbose, minimal):
    """
    Search for CVEs by keyword, product, or vulnerability name.
    
    Uses NVD (National Vulnerability Database) for reliable results.
    
    \b
    Examples:
        bsot intel cve log4j
        bsot intel cve log4j --minimal          # Just CVE IDs and scores
        bsot intel cve mongodb --limit 20
        bsot intel cve "apache struts" --json
        bsot intel cve heartbleed -v            # Full descriptions
        bsot intel cve CVE-2021-44228
    """
    import requests
    from urllib.parse import quote
    from ..utils import Colors, print_header
    
    headers = {'User-Agent': 'BSOT-SecurityToolkit/2.0'}
    
    query_upper = query.upper()
    vulnerabilities = []
    source_used = "NVD"
    
    # Build NVD API URL
    if query_upper.startswith('CVE-'):
        # Direct CVE lookup
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query_upper}"
    else:
        # Keyword search
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(query)}&resultsPerPage={limit}"
    
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulnerabilities = data.get('vulnerabilities', [])
    except requests.RequestException as e:
        if not verbose:
            pass  # Will try fallback
        else:
            click.echo(f"⚠️  NVD query failed: {e}", err=True)
    
    # Fallback to cve.org if NVD returns no results
    if not vulnerabilities and not query_upper.startswith('CVE-'):
        source_used = "CVE.org"
        try:
            # Try cve.org API
            cve_url = f"https://cveawg.mitre.org/api/cve?keyword={quote(query)}&count={limit}"
            resp = requests.get(cve_url, headers=headers, timeout=30)
            if resp.status_code == 200:
                cve_data = resp.json()
                # Convert cve.org format to NVD-like format for consistent processing
                if isinstance(cve_data, list):
                    for item in cve_data[:limit]:
                        cve_id = item.get('cveId') or item.get('id', '')
                        desc = ''
                        if 'descriptions' in item:
                            for d in item.get('descriptions', []):
                                if d.get('lang') == 'en':
                                    desc = d.get('value', '')
                                    break
                        elif 'description' in item:
                            desc = item.get('description', '')
                        
                        vulnerabilities.append({
                            'cve': {
                                'id': cve_id,
                                'descriptions': [{'lang': 'en', 'value': desc}],
                                'metrics': item.get('metrics', {}),
                                'published': item.get('published', ''),
                                'references': item.get('references', []),
                            }
                        })
        except requests.RequestException:
            pass  # Will show "no results" message
        
        # Also try GitHub Advisory Database as another fallback
        if not vulnerabilities:
            source_used = "GitHub Advisory"
            try:
                gh_url = f"https://api.github.com/advisories?keywords={quote(query)}&per_page={limit}"
                gh_headers = {**headers, 'Accept': 'application/vnd.github+json'}
                resp = requests.get(gh_url, headers=gh_headers, timeout=30)
                if resp.status_code == 200:
                    gh_data = resp.json()
                    for adv in gh_data[:limit]:
                        cve_id = None
                        for ident in adv.get('identifiers', []):
                            if ident.get('type') == 'CVE':
                                cve_id = ident.get('value')
                                break
                        if cve_id:
                            vulnerabilities.append({
                                'cve': {
                                    'id': cve_id,
                                    'descriptions': [{'lang': 'en', 'value': adv.get('summary', '')}],
                                    'metrics': {},
                                    'published': adv.get('published_at', ''),
                                    'references': [{'url': adv.get('html_url', '')}],
                                    'severity': adv.get('severity', ''),
                                }
                            })
            except requests.RequestException:
                pass
    
    if json_output:
        click.echo(json_lib.dumps(vulnerabilities, indent=2))
        return
    
    if not vulnerabilities:
        click.echo(f"No CVEs found for: {query}")
        click.echo(f"\nTry searching manually:")
        click.echo(f"  • https://www.cve.org/CVERecord/SearchResults?query={quote(query)}")
        click.echo(f"  • https://nvd.nist.gov/vuln/search/results?query={quote(query)}")
        click.echo(f"  • https://github.com/advisories?query={quote(query)}")
        sys.exit(0)
    
    # Minimal output mode - just CVE IDs and scores
    if minimal:
        for vuln in vulnerabilities[:limit]:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            
            # Get CVSS score
            cvss = None
            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore')
            elif 'cvssMetricV30' in metrics:
                cvss = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore')
            elif 'cvssMetricV2' in metrics:
                cvss = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
            
            # Severity
            if cvss and float(cvss) >= 9.0:
                sev = "CRIT"
            elif cvss and float(cvss) >= 7.0:
                sev = "HIGH"
            elif cvss and float(cvss) >= 4.0:
                sev = "MED"
            elif cvss:
                sev = "LOW"
            else:
                sev = "N/A"
            
            cvss_str = f"{cvss}" if cvss else "N/A"
            click.echo(f"{cve_id}\t{cvss_str}\t{sev}")
        return
    
    print_header(f"CVE Search: {query}")
    click.echo(f"  Found {len(vulnerabilities)} result(s) via {source_used}\n")
    
    for vuln in vulnerabilities[:limit]:
        cve_data = vuln.get('cve', {})
        cve_id = cve_data.get('id', 'Unknown')
        
        # Get CVSS score (try v3.1, then v3.0, then v2)
        cvss = None
        cvss_vector = None
        metrics = cve_data.get('metrics', {})
        
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
        
        cvss_str = f"{cvss}" if cvss else "N/A"
        
        # Color code by severity
        if cvss and float(cvss) >= 9.0:
            severity_color = Colors.RED + Colors.BOLD
            severity = "CRITICAL"
        elif cvss and float(cvss) >= 7.0:
            severity_color = Colors.RED
            severity = "HIGH"
        elif cvss and float(cvss) >= 4.0:
            severity_color = Colors.YELLOW
            severity = "MEDIUM"
        elif cvss:
            severity_color = Colors.GREEN
            severity = "LOW"
        else:
            severity_color = Colors.WHITE
            severity = "UNKNOWN"
        
        click.echo(f"  {Colors.CYAN}{Colors.BOLD}{cve_id}{Colors.RESET}")
        click.echo(f"  {severity_color}CVSS: {cvss_str} ({severity}){Colors.RESET}")
        
        # Description
        descriptions = cve_data.get('descriptions', [])
        summary = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                summary = desc.get('value', '')
                break
        
        if summary:
            if verbose:
                click.echo(f"  {summary}")
            else:
                if len(summary) > 200:
                    summary = summary[:200] + "..."
                click.echo(f"  {summary}")
        
        # Published date
        published = cve_data.get('published', '')
        if published:
            published = published.split('T')[0]
            click.echo(f"  {Colors.WHITE}Published: {published}{Colors.RESET}")
        
        # CWE (weakness type)
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe = desc.get('value', '')
                    if cwe and cwe != 'NVD-CWE-noinfo':
                        click.echo(f"  {Colors.WHITE}Weakness: {cwe}{Colors.RESET}")
                    break
        
        # References
        if verbose:
            refs = cve_data.get('references', [])[:3]
            if refs:
                click.echo(f"  {Colors.WHITE}References:{Colors.RESET}")
                for ref in refs:
                    click.echo(f"    • {ref.get('url', '')}")
        
        click.echo()
    
    # Link to NVD for more
    click.echo(f"  {Colors.WHITE}More: https://nvd.nist.gov/vuln/search/results?query={quote(query)}{Colors.RESET}")
    click.echo()

