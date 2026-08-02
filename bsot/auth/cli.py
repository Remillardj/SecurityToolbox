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



# Effective sshd configuration is what matters: an absent directive still has
# a value. Each entry is (default, checker) where checker returns a finding.
_SSHD_DEFAULTS = {
    'permitrootlogin': 'prohibit-password',
    'passwordauthentication': 'yes',
    'permitemptypasswords': 'no',
    'pubkeyauthentication': 'yes',
    'x11forwarding': 'no',
    'protocol': '2',
    'maxauthtries': '6',
    'logingracetime': '120',
    'clientaliveinterval': '0',
    'usepam': 'yes',
    'allowtcpforwarding': 'yes',
    'gatewayports': 'no',
    'hostbasedauthentication': 'no',
    'ignorerhosts': 'yes',
    'strictmodes': 'yes',
}


def _audit_sshd(config: dict) -> list:
    """Evaluate effective sshd settings, returning findings."""
    findings = []

    def effective(key):
        return config.get(key, _SSHD_DEFAULTS.get(key, ''))

    def add(severity, setting, value, message, explicit):
        findings.append({
            'severity': severity,
            'setting': setting,
            'value': value,
            'message': message,
            'source': 'config' if explicit else 'default',
        })

    root = effective('permitrootlogin')
    if root == 'yes':
        add('critical', 'PermitRootLogin', root,
            'Direct root login with a password is permitted',
            'permitrootlogin' in config)
    elif root in ('prohibit-password', 'without-password', 'forced-commands-only', 'no'):
        add('ok', 'PermitRootLogin', root, 'Root login is restricted',
            'permitrootlogin' in config)

    if effective('permitemptypasswords') == 'yes':
        add('critical', 'PermitEmptyPasswords', 'yes',
            'Accounts with empty passwords can log in',
            'permitemptypasswords' in config)

    pw = effective('passwordauthentication')
    if pw == 'yes':
        add('high', 'PasswordAuthentication', 'yes',
            'Password authentication is enabled (brute-force exposure); '
            'prefer key-based authentication',
            'passwordauthentication' in config)
    else:
        add('ok', 'PasswordAuthentication', pw, 'Password authentication is disabled',
            'passwordauthentication' in config)

    if effective('hostbasedauthentication') == 'yes':
        add('high', 'HostbasedAuthentication', 'yes',
            'Host-based authentication trusts the client host',
            'hostbasedauthentication' in config)

    if effective('ignorerhosts') == 'no':
        add('high', 'IgnoreRhosts', 'no', '.rhosts files are honored',
            'ignorerhosts' in config)

    if effective('protocol') == '1':
        add('critical', 'Protocol', '1', 'SSH protocol 1 is cryptographically broken',
            'protocol' in config)

    if effective('permituserenvironment') == 'yes':
        add('medium', 'PermitUserEnvironment', 'yes',
            'Users can set environment variables, aiding privilege escalation',
            'permituserenvironment' in config)

    try:
        tries = int(effective('maxauthtries'))
        if tries > 6:
            add('medium', 'MaxAuthTries', str(tries),
                'High authentication attempt limit aids brute-forcing',
                'maxauthtries' in config)
    except ValueError:
        pass

    if effective('x11forwarding') == 'yes':
        add('low', 'X11Forwarding', 'yes', 'X11 forwarding is enabled; disable if unused',
            'x11forwarding' in config)

    if effective('strictmodes') == 'no':
        add('medium', 'StrictModes', 'no',
            'Ownership/permission checks on user key files are disabled',
            'strictmodes' in config)

    if effective('gatewayports') == 'yes':
        add('medium', 'GatewayPorts', 'yes',
            'Forwarded ports are exposed to other hosts',
            'gatewayports' in config)

    if 'port' in config and config['port'] != '22':
        add('info', 'Port', config['port'],
            'Non-default port (obscurity only, not a control)', True)

    if 'allowusers' in config or 'allowgroups' in config:
        add('ok', 'AllowUsers/AllowGroups',
            config.get('allowusers', config.get('allowgroups', '')),
            'Login is restricted to an explicit allow-list', True)

    return findings


@auth.command('ssh-audit')
@click.argument('config_file', required=False, type=click.Path(exists=True))
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def ssh_audit(config_file, json_output):
    """
    Audit an sshd configuration for security issues.

    \b
    Settings absent from the file are evaluated at their OpenSSH default,
    so a missing PasswordAuthentication is still reported as enabled.

    \b
    Examples:
        bsot auth ssh-audit
        bsot auth ssh-audit /etc/ssh/sshd_config
        bsot auth ssh-audit sshd_config --json
    """
    import os
    from ..utils import Colors, print_header

    if not config_file:
        for candidate in ('/etc/ssh/sshd_config', '/etc/sshd_config'):
            if os.path.exists(candidate):
                config_file = candidate
                break
        if not config_file:
            click.echo("Error: no sshd_config found; pass one explicitly.", err=True)
            sys.exit(2)

    config = {}
    try:
        with open(config_file, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    key, value = parts
                    # First occurrence wins in sshd, unlike most config formats.
                    config.setdefault(key.lower(), value.strip().lower())
    except OSError as e:
        click.echo(f"Error: could not read {config_file}: {e}", err=True)
        sys.exit(2)

    findings = _audit_sshd(config)
    issues = [f for f in findings if f['severity'] not in ('ok', 'info')]

    if json_output:
        click.echo(json_lib.dumps({
            'config_file': config_file,
            'findings': findings,
            'issue_count': len(issues),
        }, indent=2))
    else:
        print_header(f"SSH Audit: {config_file}")
        colors = {
            'critical': Colors.RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.BLUE,
            'info': Colors.CYAN,
            'ok': Colors.GREEN,
        }
        for f in sorted(findings, key=lambda x: ['critical', 'high', 'medium', 'low', 'info', 'ok'].index(x['severity'])):
            c = colors.get(f['severity'], Colors.WHITE)
            src = '' if f['source'] == 'config' else f" {Colors.DIM}(sshd default){Colors.RESET}"
            click.echo(f"  {c}[{f['severity'].upper()}]{Colors.RESET} {f['setting']} = {f['value']}{src}")
            click.echo(f"        {Colors.DIM}{f['message']}{Colors.RESET}")
        click.echo()
        click.echo(f"  {len(issues)} issue(s) found.")
        click.echo()

    if issues:
        sys.exit(1)
