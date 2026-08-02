"""
CLI commands for the phishing analysis module.
"""

import click
import sys


@click.group()
def phishing():
    """Phishing email analysis tools."""
    pass


@phishing.command()
@click.argument('email_file', type=click.Path(exists=True))
@click.option('--openai-key', envvar='OPENAI_API_KEY', help='OpenAI API key for AI analysis')
@click.option('--anthropic-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key for AI analysis')
@click.option('--virustotal-key', envvar='VIRUSTOTAL_API_KEY', help='VirusTotal API key')
@click.option('--abuseipdb-key', envvar='ABUSEIPDB_API_KEY', help='AbuseIPDB API key')
@click.option('--llm-provider', type=click.Choice(['openai', 'anthropic']), default='openai', 
              help='LLM provider to use')
@click.option('--quick', '-q', is_flag=True, help='Quick mode - skip API calls')
@click.option('--output', '-o', type=click.Path(), help='Export report to file (JSON or HTML)')
@click.option('--format', '-f', type=click.Choice(['json', 'html']), default='json',
              help='Output format for exported report')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--json', 'json_output', is_flag=True, help='Output raw JSON to stdout')
def analyze(email_file, openai_key, anthropic_key, virustotal_key, abuseipdb_key,
            llm_provider, quick, output, format, verbose, json_output):
    """
    Analyze an email file for phishing indicators.
    
    Performs comprehensive analysis including:
    - Email parsing and IOC extraction
    - Header authentication (SPF/DKIM/DMARC)
    - Reputation checks via VirusTotal/AbuseIPDB
    - AI-powered phishing detection
    
    Example:
        bsot phishing analyze suspicious.eml
        bsot phishing analyze email.eml --quick
        bsot phishing analyze email.eml -o report.html -f html
    """
    from .analyzer import PhishingAnalyzer
    import json as json_lib
    
    # Determine which LLM key to use
    llm_key = anthropic_key if llm_provider == 'anthropic' else openai_key
    
    # Initialize analyzer
    analyzer = PhishingAnalyzer(
        openai_api_key=openai_key if llm_provider == 'openai' else None,
        anthropic_api_key=anthropic_key if llm_provider == 'anthropic' else None,
        virustotal_api_key=virustotal_key,
        abuseipdb_api_key=abuseipdb_key,
        llm_provider=llm_provider
    )
    
    try:
        # Run analysis
        if quick:
            result = analyzer.analyze_quick(email_file)
        else:
            result = analyzer.analyze(
                email_file,
                skip_reputation=not virustotal_key and not abuseipdb_key,
                skip_llm=not llm_key,
                verbose=verbose and not json_output
            )
        
        # Output
        if json_output:
            click.echo(json_lib.dumps(result.report, indent=2, default=str))
        else:
            analyzer.print_report(result, verbose=verbose)
        
        # Export if requested
        if output:
            analyzer.export_report(result, output, format)
            click.echo(f"\n📄 Report exported to: {output}")
        
        # Exit code based on verdict
        if result.verdict and result.verdict.is_phishing:
            sys.exit(1)
        sys.exit(0)
        
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Error during analysis: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


@phishing.command()
@click.argument('email_file', type=click.Path(exists=True))
@click.option('--include-safe', is_flag=True, help='Include known safe domains')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def extract_iocs(email_file, include_safe, json_output):
    """
    Extract IOCs (URLs, IPs, domains, hashes) from an email.
    
    Example:
        bsot phishing extract-iocs suspicious.eml
        bsot phishing extract-iocs email.eml --json
    """
    from .email_parser import EmailParser
    from .ioc_extractor import extract_iocs_from_email, IOCExtractor
    from ..utils import print_header, print_subheader
    import json as json_lib
    
    parser = EmailParser()
    email = parser.parse(email_file)
    
    # Use custom extractor if include_safe is set
    if include_safe:
        extractor = IOCExtractor(include_safe_domains=True)
        iocs = extractor.extract_all(
            f"{email.subject}\n{email.body_text}",
            email.body_html
        )
    else:
        iocs = extract_iocs_from_email(email)
    
    if json_output:
        click.echo(json_lib.dumps(iocs.to_dict(), indent=2))
    else:
        print_header("Extracted IOCs")
        
        click.echo(f"  Total IOCs found: {iocs.total_count}\n")
        
        # Indicators are defanged on the way out (see utils.safe) so the
        # output is safe to paste into a ticket; --no-defang opts out.
        from ..utils import safe

        if iocs.urls:
            print_subheader(f"URLs ({len(iocs.urls)})")
            for url in iocs.urls:
                click.echo(f"  • {safe(url)}")

        if iocs.domains:
            print_subheader(f"Domains ({len(iocs.domains)})")
            for domain in iocs.domains:
                click.echo(f"  • {safe(domain)}")

        if iocs.ip_addresses:
            print_subheader(f"IP Addresses ({len(iocs.ip_addresses)})")
            for ip in iocs.ip_addresses:
                click.echo(f"  • {safe(ip)}")

        if iocs.email_addresses:
            print_subheader(f"Email Addresses ({len(iocs.email_addresses)})")
            for email_addr in iocs.email_addresses:
                click.echo(f"  • {safe(email_addr)}")
        
        for hash_type, hashes in iocs.file_hashes.items():
            if hashes:
                print_subheader(f"{hash_type.upper()} Hashes ({len(hashes)})")
                for h in hashes:
                    click.echo(f"  • {h}")
        
        if iocs.bitcoin_addresses:
            print_subheader(f"Bitcoin Addresses ({len(iocs.bitcoin_addresses)})")
            for addr in iocs.bitcoin_addresses:
                click.echo(f"  • {addr}")


@phishing.command()
@click.argument('email_file', type=click.Path(exists=True))
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def headers(email_file, json_output):
    """
    Analyze email headers for authentication and security issues.
    
    Checks SPF, DKIM, DMARC authentication and routing.
    
    Example:
        bsot phishing headers email.eml
    """
    from .email_parser import EmailParser
    from .header_analyzer import analyze_email_headers
    from ..utils import Colors, print_header, print_subheader, print_finding
    import json as json_lib
    
    parser = EmailParser()
    email = parser.parse(email_file)
    result = analyze_email_headers(email)
    
    if json_output:
        output = {
            'authentication_score': result.auth_score,
            'is_authenticated': result.is_authenticated,
            'spf': {
                'result': result.spf_result.result if result.spf_result else None,
                'details': result.spf_result.details if result.spf_result else None,
            } if result.spf_result else None,
            'dkim': {
                'result': result.dkim_result.result if result.dkim_result else None,
                'domain': result.dkim_result.domain if result.dkim_result else None,
            } if result.dkim_result else None,
            'dmarc': {
                'result': result.dmarc_result.result if result.dmarc_result else None,
            } if result.dmarc_result else None,
            'envelope_from': result.envelope_from,
            'header_from': result.header_from,
            'reply_to': result.reply_to,
            'from_domain_mismatch': result.from_domain_mismatch,
            'hops': len(result.received_hops),
            'transit_time_seconds': result.total_transit_time,
            'warnings': result.warnings,
            'suspicious_indicators': result.suspicious_indicators,
        }
        click.echo(json_lib.dumps(output, indent=2))
    else:
        print_header("Email Header Analysis")
        
        # Authentication results
        print_subheader("Authentication")
        
        def auth_status(auth_result):
            if not auth_result:
                return f"{Colors.YELLOW}NONE{Colors.RESET}"
            if auth_result.result == 'pass':
                return f"{Colors.GREEN}PASS{Colors.RESET}"
            elif auth_result.result in ('fail', 'softfail'):
                return f"{Colors.RED}{auth_result.result.upper()}{Colors.RESET}"
            return f"{Colors.YELLOW}{auth_result.result.upper()}{Colors.RESET}"
        
        click.echo(f"  SPF:   {auth_status(result.spf_result)}")
        click.echo(f"  DKIM:  {auth_status(result.dkim_result)}")
        click.echo(f"  DMARC: {auth_status(result.dmarc_result)}")
        click.echo(f"  Score: {result.auth_score}/100")
        
        # Sender info
        print_subheader("Sender Information")
        click.echo(f"  Header From:   {result.header_from or 'N/A'}")
        click.echo(f"  Envelope From: {result.envelope_from or 'N/A'}")
        click.echo(f"  Reply-To:      {result.reply_to or '(same as From)'}")
        
        if result.from_domain_mismatch:
            print_finding('high', 'From domain mismatch detected!')
        
        # Routing
        print_subheader("Routing")
        click.echo(f"  Mail hops:     {len(result.received_hops)}")
        click.echo(f"  Transit time:  {result.total_transit_time}s")
        
        # Issues
        if result.warnings or result.suspicious_indicators:
            print_subheader("Issues Found")
            
            for indicator in result.suspicious_indicators:
                print_finding('high', indicator)
            
            for warning in result.warnings:
                print_finding('medium', warning)


@phishing.command()
@click.argument('email_file', type=click.Path(exists=True))
@click.option('--openai-key', envvar='OPENAI_API_KEY', help='OpenAI API key')
@click.option('--anthropic-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--provider', type=click.Choice(['openai', 'anthropic']), default='openai')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def ai_analyze(email_file, openai_key, anthropic_key, provider, json_output):
    """
    Analyze email using AI/LLM for phishing detection.
    
    Requires an API key (OpenAI or Anthropic).
    
    Example:
        bsot phishing ai-analyze email.eml --openai-key $OPENAI_API_KEY
        OPENAI_API_KEY=xxx bsot phishing ai-analyze email.eml
    """
    from .email_parser import EmailParser
    from .ioc_extractor import extract_iocs_from_email
    from .llm_analyzer import analyze_email_with_llm
    from ..utils import Colors, print_header, print_subheader, print_finding
    import json as json_lib
    
    api_key = anthropic_key if provider == 'anthropic' else openai_key
    
    if not api_key:
        click.echo("Error: API key required. Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable, "
                   "or use --openai-key / --anthropic-key option.", err=True)
        sys.exit(1)
    
    parser = EmailParser()
    email = parser.parse(email_file)
    iocs = extract_iocs_from_email(email)
    
    click.echo("🤖 Running AI analysis...")
    
    result = analyze_email_with_llm(
        email,
        iocs,
        api_key=api_key,
        provider=provider
    )
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
    else:
        print_header("AI Phishing Analysis")
        
        # Verdict
        verdict_colors = {
            'phishing': Colors.RED + Colors.BOLD,
            'suspicious': Colors.YELLOW + Colors.BOLD,
            'legitimate': Colors.GREEN + Colors.BOLD,
        }
        color = verdict_colors.get(result.verdict, Colors.WHITE)
        
        click.echo(f"  {color}Verdict: {result.verdict.upper()}{Colors.RESET}")
        click.echo(f"  Confidence: {int(result.confidence * 100)}%")
        click.echo(f"  Model: {result.model_used}")
        
        if result.summary:
            print_subheader("Summary")
            click.echo(f"  {result.summary}")
        
        if result.social_engineering_tactics:
            print_subheader("Social Engineering Tactics")
            for tactic in result.social_engineering_tactics:
                print_finding('high', tactic)
        
        if result.impersonation_indicators:
            print_subheader("Impersonation Indicators")
            for indicator in result.impersonation_indicators:
                print_finding('high', indicator)
        
        if result.urgency_pressure_tactics:
            print_subheader("Pressure/Urgency Tactics")
            for tactic in result.urgency_pressure_tactics:
                print_finding('medium', tactic)
        
        if result.suspicious_requests:
            print_subheader("Suspicious Requests")
            for req in result.suspicious_requests:
                print_finding('high', req)
        
        if result.recommendations:
            print_subheader("Recommendations")
            for i, rec in enumerate(result.recommendations, 1):
                click.echo(f"  {i}. {rec}")


@phishing.command()
@click.argument('email_file', type=click.Path(exists=True))
@click.option('--virustotal-key', envvar='VIRUSTOTAL_API_KEY', help='VirusTotal API key')
@click.option('--abuseipdb-key', envvar='ABUSEIPDB_API_KEY', help='AbuseIPDB API key')
@click.option('--max-iocs', default=10, help='Max IOCs to check per type')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def reputation(email_file, virustotal_key, abuseipdb_key, max_iocs, json_output):
    """
    Check reputation of IOCs found in email.
    
    Queries VirusTotal, AbuseIPDB for URL/IP/domain reputation.
    
    Example:
        bsot phishing reputation email.eml --virustotal-key $VT_KEY
    """
    from .email_parser import EmailParser
    from .ioc_extractor import extract_iocs_from_email
    from .reputation import ReputationChecker
    from ..utils import Colors, print_header, print_subheader, print_finding, defang_url
    import json as json_lib
    
    if not virustotal_key and not abuseipdb_key:
        click.echo("Error: At least one API key required (VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY)", 
                   err=True)
        sys.exit(1)
    
    parser = EmailParser()
    email = parser.parse(email_file)
    iocs = extract_iocs_from_email(email)
    
    if iocs.total_count == 0:
        click.echo("No IOCs found in email.")
        sys.exit(0)
    
    click.echo(f"🌐 Checking {iocs.total_count} IOCs (max {max_iocs} per type)...")
    
    checker = ReputationChecker(
        virustotal_key=virustotal_key,
        abuseipdb_key=abuseipdb_key
    )
    
    results = checker.check_all_iocs(iocs, max_per_type=max_iocs)
    summary = checker.get_summary(results)
    
    if json_output:
        click.echo(json_lib.dumps(summary, indent=2))
    else:
        print_header("IOC Reputation Check")
        
        click.echo(f"  Total checked: {summary['total_checked']}")
        click.echo(f"  {Colors.RED}Malicious: {summary['malicious_count']}{Colors.RESET}")
        click.echo(f"  {Colors.YELLOW}Suspicious: {summary['suspicious_count']}{Colors.RESET}")
        click.echo(f"  {Colors.GREEN}Clean: {summary['clean_count']}{Colors.RESET}")
        
        if summary['malicious_iocs']:
            print_subheader("Malicious IOCs")
            for ioc in summary['malicious_iocs']:
                ioc_display = defang_url(ioc['ioc']) if ioc['type'] == 'url' else ioc['ioc']
                print_finding('critical', f"[{ioc['type']}] {ioc_display}", 
                            f"Score: {ioc['score']:.2f}")
        
        if summary['suspicious_iocs']:
            print_subheader("Suspicious IOCs")
            for ioc in summary['suspicious_iocs']:
                ioc_display = defang_url(ioc['ioc']) if ioc['type'] == 'url' else ioc['ioc']
                print_finding('medium', f"[{ioc['type']}] {ioc_display}",
                            f"Score: {ioc['score']:.2f}")
    
    # Exit code based on findings
    if summary['malicious_count'] > 0:
        sys.exit(1)
    sys.exit(0)



@phishing.command()
@click.argument('url', required=False)
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True),
              help='Read URLs from a file, one per line')
@click.option('--expand', is_flag=True,
              help='Follow redirects to reveal the final destination')
@click.option('--no-cache', is_flag=True, help='Bypass the local cache')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.pass_context
def url(ctx, url, input_file, expand, no_cache, json_output):
    """
    Analyze a URL without needing a full email.

    \b
    Checks reputation across configured sources and, with --expand, follows
    redirects to reveal where a shortener actually lands. Accepts defanged
    input, so a URL copied out of a ticket can be pasted straight in.

    \b
    Examples:
        bsot phishing url "hxxp[://]suspicious[.]xyz/login"
        bsot phishing url https://bit.ly/abc --expand
        cat urls.txt | bsot phishing url -
        bsot phishing url https://example.com --json
    """
    import json as json_lib
    import re
    from urllib.parse import urlparse

    from .reputation import ReputationChecker
    from ..config import config
    from ..intel.ioc_utils import refang
    from ..utils import Colors, print_header, print_subheader, safe

    # Gather targets
    targets = []
    if url == '-' or (not url and not input_file):
        targets = [line.strip() for line in sys.stdin if line.strip()]
    elif input_file:
        with open(input_file) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif url:
        targets = [url]

    if not targets:
        click.echo("Error: no URL provided.", err=True)
        sys.exit(2)

    # Analysts paste defanged URLs out of tickets; accept them.
    targets = [refang(t) for t in targets]

    # urlparse is lenient enough to accept "not a url at all" as a netloc,
    # so the host is validated against hostname syntax rather than truthiness.
    host_pattern = re.compile(
        r'^(?:\[[0-9a-fA-F:]+\]|'                              # IPv6 literal
        r'\d{1,3}(?:\.\d{1,3}){3}|'                            # IPv4
        r'localhost|'
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # domain labels
        r'[a-zA-Z]{2,})$'
    )
    for target in targets:
        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.hostname or ''
        if not host_pattern.match(host):
            click.echo(f"Error: '{target}' is not a valid URL.", err=True)
            sys.exit(2)

    checker = ReputationChecker(
        virustotal_key=config.virustotal_api_key,
        urlscan_key=config.urlscan_api_key,
    )
    has_sources = bool(config.virustotal_api_key or config.urlscan_api_key)

    reports = []
    for target in targets:
        parsed = urlparse(target if '://' in target else f'http://{target}')
        entry = {
            'url': target,
            'scheme': parsed.scheme,
            'host': parsed.hostname or '',
            'port': parsed.port,
            'path': parsed.path,
            'redirects': [],
            'final_url': None,
            'reputation': None,
        }

        if expand:
            import requests
            try:
                response = requests.get(
                    target, timeout=15, allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; bsot)'},
                )
                entry['redirects'] = [r.url for r in response.history]
                entry['final_url'] = response.url
                entry['status_code'] = response.status_code
            except requests.exceptions.RequestException as e:
                entry['expand_error'] = str(e)

        if has_sources:
            # Reputation is checked against the final destination when known,
            # since that is what a victim actually reaches.
            lookup_target = entry.get('final_url') or target
            try:
                agg = checker.check_url(lookup_target)
                entry['reputation'] = {
                    'verdict': agg.verdict,
                    'max_score': agg.max_score,
                    'sources': [r.to_dict() for r in agg.results],
                }
            except Exception as e:
                entry['reputation'] = {'error': str(e)}

        reports.append(entry)

    if json_output:
        click.echo(json_lib.dumps(
            {'count': len(reports), 'results': reports}, indent=2, default=str
        ))
    else:
        for entry in reports:
            print_header(f"URL Analysis: {safe(entry['url'])}")
            click.echo(f"  Host: {safe(entry['host'])}")
            if entry.get('port'):
                click.echo(f"  Port: {entry['port']}")
            if entry['scheme'] != 'https':
                click.echo(f"  {Colors.YELLOW}Scheme is {entry['scheme']}, not https{Colors.RESET}")

            if entry['redirects']:
                print_subheader(f"Redirect chain ({len(entry['redirects'])} hops)")
                for hop in entry['redirects']:
                    click.echo(f"  → {safe(hop)}")
                click.echo(f"  {Colors.BOLD}final:{Colors.RESET} {safe(entry['final_url'] or '')}")
            elif entry.get('final_url'):
                click.echo(f"  No redirects (HTTP {entry.get('status_code')})")
            elif entry.get('expand_error'):
                click.echo(f"  {Colors.DIM}Could not expand: {entry['expand_error']}{Colors.RESET}")

            reputation = entry['reputation']
            if reputation is None:
                click.echo()
                click.echo(f"  {Colors.DIM}No reputation sources configured. "
                           f"Run 'bsot config check' to see what is missing.{Colors.RESET}")
            elif reputation.get('error'):
                click.echo(f"  {Colors.YELLOW}Reputation lookup failed: "
                           f"{reputation['error']}{Colors.RESET}")
            else:
                print_subheader('Reputation')
                colors = {'malicious': Colors.RED + Colors.BOLD,
                          'suspicious': Colors.YELLOW, 'clean': Colors.GREEN}
                color = colors.get(reputation['verdict'], Colors.WHITE)
                click.echo(f"  Verdict: {color}{reputation['verdict'].upper()}{Colors.RESET}")
                for source in reputation['sources']:
                    click.echo(f"    {source.get('source', '?')}: "
                               f"{source.get('detections', 0)} detection(s)")
            click.echo()

    if any((r['reputation'] or {}).get('verdict') in ('malicious', 'suspicious')
           for r in reports):
        sys.exit(1)
