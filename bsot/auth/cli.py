"""
CLI commands for the authentication module.
"""

import click
import sys
import json as json_lib


@click.group()
def auth():
    """Authentication security tools."""
    pass


@auth.command('password-analyze')
@click.argument('password', required=False)
@click.option('--check-breach', is_flag=True, help='Check against Have I Been Pwned')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def password_analyze(password, check_breach, json_output):
    """
    Analyze password strength.
    
    \b
    Examples:
        bsot auth password-analyze "MyP@ssw0rd!"
        bsot auth password-analyze --check-breach
    """
    from .password import PasswordAnalyzer
    from ..utils import Colors, print_header, print_subheader
    
    # Get password securely if not provided
    if not password:
        password = click.prompt('Password', hide_input=True)
    
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password, check_breach=check_breach)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header("Password Analysis")
    
    # Strength indicator
    strength_colors = {
        'strong': Colors.GREEN,
        'good': Colors.GREEN,
        'fair': Colors.YELLOW,
        'weak': Colors.RED,
    }
    color = strength_colors.get(result.strength, Colors.WHITE)
    
    click.echo(f"\n  {color}{Colors.BOLD}Strength: {result.strength.upper()}{Colors.RESET}")
    click.echo(f"  Score: {result.score}/100")
    
    # Details
    print_subheader("Details")
    click.echo(f"  Length: {result.length} characters")
    click.echo(f"  Entropy: {result.entropy:.1f} bits")
    
    # Character classes
    classes = []
    if result.has_uppercase:
        classes.append('uppercase')
    if result.has_lowercase:
        classes.append('lowercase')
    if result.has_digits:
        classes.append('digits')
    if result.has_special:
        classes.append('special')
    click.echo(f"  Character types: {', '.join(classes) if classes else 'none'}")
    
    # Patterns
    if result.patterns:
        print_subheader("Patterns Detected")
        for pattern in result.patterns:
            click.echo(f"  ⚠️  {pattern}")
    
    # Breach check
    if check_breach:
        print_subheader("Breach Check")
        if result.breach_count == 0:
            click.echo(f"  {Colors.GREEN}✓ Not found in known breaches{Colors.RESET}")
        elif result.breach_count > 0:
            click.echo(f"  {Colors.RED}✗ Found in {result.breach_count:,} data breaches!{Colors.RESET}")
        else:
            click.echo(f"  {Colors.YELLOW}? Could not check breaches{Colors.RESET}")
    
    # Recommendations
    if result.recommendations:
        print_subheader("Recommendations")
        for rec in result.recommendations:
            click.echo(f"  • {rec}")
    
    click.echo()
    
    if result.strength == 'weak':
        sys.exit(1)


@auth.command('jwt-decode')
@click.argument('token', required=False)
@click.option('--verify', help='Key for signature verification')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def jwt_decode(token, verify, json_output):
    """
    Decode and analyze JWT tokens.
    
    \b
    Examples:
        bsot auth jwt-decode "eyJhbGciOiJIUzI1NiIs..."
        bsot auth jwt-decode --verify "my-secret-key"
    """
    from .jwt import JWTDecoder
    from ..utils import Colors, print_header, print_subheader
    
    # Get token from stdin if not provided
    if not token:
        token = sys.stdin.read().strip()
    
    if not token:
        click.echo("Error: No token provided", err=True)
        sys.exit(2)
    
    decoder = JWTDecoder()
    result = decoder.decode(token, verify_key=verify)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    print_header("JWT Analysis")
    
    if result.error:
        click.echo(f"\n  {Colors.RED}❌ Error: {result.error}{Colors.RESET}")
        sys.exit(2)
    
    # Header
    print_subheader("Header")
    click.echo(f"  Algorithm: {result.algorithm}")
    for key, value in result.header.items():
        if key != 'alg':
            click.echo(f"  {key}: {value}")
    
    # Payload
    print_subheader("Payload")
    for key, value in result.payload.items():
        if key in ('exp', 'iat', 'nbf'):
            # Format timestamps
            import datetime
            try:
                dt = datetime.datetime.fromtimestamp(value)
                click.echo(f"  {key}: {value} ({dt.isoformat()})")
            except (ValueError, OSError):
                click.echo(f"  {key}: {value}")
        else:
            value_str = str(value)
            if len(value_str) > 50:
                value_str = value_str[:50] + '...'
            click.echo(f"  {key}: {value_str}")
    
    # Expiration
    print_subheader("Expiration")
    if result.expiration:
        if result.is_expired:
            click.echo(f"  {Colors.RED}✗ EXPIRED{Colors.RESET}")
        else:
            click.echo(f"  {Colors.GREEN}✓ Valid{Colors.RESET}")
        click.echo(f"  {result.expiration_human}")
    else:
        click.echo(f"  {Colors.YELLOW}! No expiration set{Colors.RESET}")
    
    # Signature verification
    if verify:
        print_subheader("Signature Verification")
        if result.signature_verified:
            click.echo(f"  {Colors.GREEN}✓ Signature valid{Colors.RESET}")
        else:
            click.echo(f"  {Colors.RED}✗ Signature invalid{Colors.RESET}")
    
    # Security
    if result.vulnerabilities or result.warnings:
        print_subheader("Security")
        for vuln in result.vulnerabilities:
            click.echo(f"  {Colors.RED}✗ {vuln}{Colors.RESET}")
        for warning in result.warnings:
            click.echo(f"  {Colors.YELLOW}! {warning}{Colors.RESET}")
    
    click.echo()
    
    if result.is_expired or result.vulnerabilities:
        sys.exit(1)

