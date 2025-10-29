#!/usr/bin/env python3
"""
Authentication and cryptography security commands
"""

import click
import re
import json
import base64
from typing import Dict, List

@click.group('auth')
def auth_group():
    """Authentication and cryptography security tools"""
    pass

@auth_group.command('password-analyze')
@click.argument('password', required=False)
@click.option('-f', '--file', type=click.Path(exists=True), help='File containing passwords (one per line)')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed analysis')
def password_analyze(password, file, verbose):
    """Analyze password strength and security

    Examples:
        bsot auth password-analyze "MyP@ssw0rd"
        bsot auth password-analyze --file passwords.txt
        bsot auth password-analyze "test123" --verbose
    """
    import string

    def analyze_password(pwd):
        """Analyze a single password"""
        score = 0
        feedback = []
        warnings = []

        # Length check
        length = len(pwd)
        if length < 8:
            warnings.append("Password is too short (< 8 characters)")
        elif length < 12:
            feedback.append("Password length is acceptable but could be longer")
            score += 1
        elif length < 16:
            score += 2
            feedback.append("Good password length")
        else:
            score += 3
            feedback.append("Excellent password length")

        # Character variety
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(c in string.punctuation for c in pwd)

        char_types = sum([has_lower, has_upper, has_digit, has_special])

        if char_types < 2:
            warnings.append("Password uses only one character type")
        elif char_types == 2:
            score += 1
            feedback.append("Uses multiple character types")
        elif char_types == 3:
            score += 2
            feedback.append("Good variety of character types")
        else:
            score += 3
            feedback.append("Excellent variety of character types")

        # Common patterns
        common_patterns = [
            (r'12345', 'Contains sequential numbers'),
            (r'qwerty|asdf', 'Contains keyboard pattern'),
            (r'password|passwd|pass', 'Contains the word "password"'),
            (r'admin|root|user', 'Contains common username'),
            (r'(.)\\1{2,}', 'Contains repeated characters'),
            (r'^[a-zA-Z]+$', 'Only letters (no numbers/symbols)'),
            (r'^[0-9]+$', 'Only numbers'),
        ]

        for pattern, message in common_patterns:
            if re.search(pattern, pwd, re.IGNORECASE):
                warnings.append(message)
                score -= 1

        # Common weak passwords
        weak_passwords = [
            'password', 'password123', '12345678', 'qwerty', 'abc123',
            'monkey', 'letmein', 'trustno1', 'dragon', 'baseball',
            'iloveyou', 'master', 'sunshine', 'ashley', 'bailey'
        ]

        if pwd.lower() in weak_passwords:
            warnings.append("This is a commonly used weak password")
            score = 0

        # Calculate final score
        strength = 'Very Weak'
        if score >= 8:
            strength = 'Very Strong'
        elif score >= 6:
            strength = 'Strong'
        elif score >= 4:
            strength = 'Moderate'
        elif score >= 2:
            strength = 'Weak'

        return {
            'password': pwd,
            'length': length,
            'strength': strength,
            'score': max(0, score),
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_special': has_special,
            'feedback': feedback,
            'warnings': warnings
        }

    # Process passwords
    passwords_to_check = []

    if file:
        with open(file, 'r') as f:
            passwords_to_check = [line.strip() for line in f if line.strip()]
    elif password:
        passwords_to_check = [password]
    else:
        click.echo("Error: Provide a password or use --file", err=True)
        return

    # Analyze each password
    for pwd in passwords_to_check:
        result = analyze_password(pwd)

        click.echo("=" * 60)
        click.echo(f"Password: {'*' * len(pwd)}")
        click.echo(f"Length: {result['length']}")
        click.echo(f"Strength: {result['strength']} (Score: {result['score']}/10)")

        if verbose:
            click.echo(f"\nCharacter Types:")
            click.echo(f"  Lowercase: {'✅' if result['has_lower'] else '❌'}")
            click.echo(f"  Uppercase: {'✅' if result['has_upper'] else '❌'}")
            click.echo(f"  Digits: {'✅' if result['has_digit'] else '❌'}")
            click.echo(f"  Special: {'✅' if result['has_special'] else '❌'}")

        if result['feedback']:
            click.echo(f"\n✅ Strengths:")
            for item in result['feedback']:
                click.echo(f"  - {item}")

        if result['warnings']:
            click.echo(f"\n⚠️  Weaknesses:")
            for item in result['warnings']:
                click.echo(f"  - {item}")

        click.echo()

@auth_group.command('jwt-decode')
@click.argument('token')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed information')
@click.option('--verify', help='Secret key to verify signature')
def jwt_decode(token, verbose, verify):
    """Decode and analyze JWT tokens

    Examples:
        bsot auth jwt-decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        bsot auth jwt-decode <token> --verbose
        bsot auth jwt-decode <token> --verify "secret-key"
    """
    import hmac
    import hashlib
    from datetime import datetime

    try:
        # Split the token
        parts = token.split('.')
        if len(parts) != 3:
            click.echo("Error: Invalid JWT format (expected 3 parts)", err=True)
            return

        header_encoded, payload_encoded, signature_encoded = parts

        # Decode header and payload
        def decode_base64url(data):
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)

        header = json.loads(decode_base64url(header_encoded))
        payload = json.loads(decode_base64url(payload_encoded))

        click.echo("=" * 60)
        click.echo("JWT TOKEN ANALYSIS")
        click.echo("=" * 60)

        click.echo("\nHEADER:")
        click.echo(json.dumps(header, indent=2))

        click.echo("\nPAYLOAD:")
        click.echo(json.dumps(payload, indent=2))

        # Check expiration
        warnings = []
        if 'exp' in payload:
            exp_time = datetime.fromtimestamp(payload['exp'])
            now = datetime.now()
            if exp_time < now:
                warnings.append(f"Token is EXPIRED (expired: {exp_time})")
            else:
                time_left = exp_time - now
                click.echo(f"\nExpiration: {exp_time} ({time_left.days} days remaining)")

        # Check algorithm
        alg = header.get('alg', 'none')
        if alg == 'none':
            warnings.append("Algorithm is 'none' - token is NOT signed!")
        elif alg in ['HS256', 'HS384', 'HS512']:
            click.echo(f"\nAlgorithm: {alg} (HMAC)")
        elif alg in ['RS256', 'RS384', 'RS512']:
            click.echo(f"\nAlgorithm: {alg} (RSA)")
        else:
            click.echo(f"\nAlgorithm: {alg}")

        # Verify signature if key provided
        if verify:
            if alg.startswith('HS'):
                message = f"{header_encoded}.{payload_encoded}".encode()
                hash_func = {
                    'HS256': hashlib.sha256,
                    'HS384': hashlib.sha384,
                    'HS512': hashlib.sha512
                }.get(alg)

                if hash_func:
                    expected_signature = base64.urlsafe_b64encode(
                        hmac.new(verify.encode(), message, hash_func).digest()
                    ).rstrip(b'=')

                    actual_signature = signature_encoded.encode()

                    if expected_signature == actual_signature:
                        click.echo("\n✅ Signature is VALID")
                    else:
                        warnings.append("Signature is INVALID")
            else:
                warnings.append(f"Signature verification not supported for {alg}")

        if warnings:
            click.echo(f"\n⚠️  WARNINGS:")
            for warning in warnings:
                click.echo(f"  - {warning}")

        if verbose:
            click.echo(f"\nRAW TOKEN:")
            click.echo(f"  Header: {header_encoded}")
            click.echo(f"  Payload: {payload_encoded}")
            click.echo(f"  Signature: {signature_encoded}")

    except json.JSONDecodeError:
        click.echo("Error: Invalid JWT - unable to decode JSON", err=True)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)

@auth_group.command('ssh-audit')
@click.argument('config_file', type=click.Path(exists=True), required=False)
@click.option('-v', '--verbose', is_flag=True, help='Show detailed analysis')
def ssh_audit(config_file, verbose):
    """Audit SSH configuration for security issues

    Examples:
        bsot auth ssh-audit
        bsot auth ssh-audit /etc/ssh/sshd_config
        bsot auth ssh-audit ~/.ssh/config --verbose
    """
    import os

    # Default SSH config locations
    if not config_file:
        possible_configs = [
            '/etc/ssh/sshd_config',
            '/etc/sshd_config',
            os.path.expanduser('~/.ssh/config')
        ]
        for path in possible_configs:
            if os.path.exists(path):
                config_file = path
                break

        if not config_file:
            click.echo("Error: No SSH config file found", err=True)
            return

    click.echo(f"Auditing SSH configuration: {config_file}")
    click.echo("=" * 60)

    warnings = []
    recommendations = []
    secure_settings = []

    try:
        with open(config_file, 'r') as f:
            config_lines = f.readlines()

        config = {}
        for line in config_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ' ' in line:
                key, value = line.split(None, 1)
                config[key.lower()] = value.lower()

        # Security checks
        if config.get('passwordauthentication') == 'yes':
            warnings.append("Password authentication is enabled - use key-based authentication")
        else:
            secure_settings.append("Password authentication is disabled")

        if config.get('permitrootlogin') == 'yes':
            warnings.append("Root login is permitted - should be disabled")
        elif config.get('permitrootlogin') == 'no':
            secure_settings.append("Root login is disabled")

        if config.get('permitemptypasswords') == 'yes':
            warnings.append("Empty passwords are allowed - CRITICAL security issue")

        if config.get('x11forwarding') == 'yes':
            recommendations.append("X11 forwarding is enabled - disable if not needed")

        if 'port' in config:
            port = config['port']
            if port == '22':
                recommendations.append("Using default SSH port (22) - consider changing to reduce automated attacks")
            else:
                secure_settings.append(f"Using non-standard port: {port}")

        # Check for weak ciphers/MACs
        if 'ciphers' in config:
            weak_ciphers = ['3des', 'arcfour', 'blowfish', 'cast128']
            ciphers = config['ciphers']
            if any(weak in ciphers for weak in weak_ciphers):
                warnings.append("Weak ciphers are enabled")
        else:
            recommendations.append("No explicit cipher configuration - review default ciphers")

        # Output results
        if secure_settings:
            click.echo("\n✅ SECURE SETTINGS:")
            for setting in secure_settings:
                click.echo(f"  - {setting}")

        if warnings:
            click.echo("\n⚠️  SECURITY WARNINGS:")
            for warning in warnings:
                click.echo(f"  - {warning}")

        if recommendations:
            click.echo("\n💡 RECOMMENDATIONS:")
            for rec in recommendations:
                click.echo(f"  - {rec}")

        if verbose:
            click.echo("\nFULL CONFIGURATION:")
            for key, value in config.items():
                click.echo(f"  {key}: {value}")

    except PermissionError:
        click.echo(f"Error: Permission denied reading {config_file}", err=True)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
