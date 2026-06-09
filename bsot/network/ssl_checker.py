"""
SSL/TLS Certificate Checker
Comprehensive SSL/TLS security analysis.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class SSLResult:
    """SSL/TLS check result."""
    host: str
    port: int = 443
    
    # Connection status
    connected: bool = False
    error: str = ""
    
    # Certificate info
    cert_subject: Dict[str, str] = field(default_factory=dict)
    cert_issuer: Dict[str, str] = field(default_factory=dict)
    cert_version: int = 0
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_expiring_soon: bool = False  # < 30 days
    
    # Subject Alternative Names
    san: List[str] = field(default_factory=list)
    
    # Protocol/cipher
    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    
    # Security assessment
    grade: str = ""  # A, B, C, D, F
    warnings: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    
    # Chain
    cert_chain_valid: bool = True
    chain_length: int = 0
    
    def to_dict(self) -> dict:
        return {
            'host': self.host,
            'port': self.port,
            'connected': self.connected,
            'error': self.error,
            'certificate': {
                'subject': self.cert_subject,
                'issuer': self.cert_issuer,
                'version': self.cert_version,
                'serial_number': self.serial_number,
                'not_before': self.not_before,
                'not_after': self.not_after,
                'days_until_expiry': self.days_until_expiry,
                'is_expired': self.is_expired,
                'is_expiring_soon': self.is_expiring_soon,
                'san': self.san,
            },
            'protocol': {
                'version': self.protocol_version,
                'cipher': self.cipher_name,
                'bits': self.cipher_bits,
            },
            'security': {
                'grade': self.grade,
                'warnings': self.warnings,
                'vulnerabilities': self.vulnerabilities,
            },
            'chain_valid': self.cert_chain_valid,
        }


class SSLChecker:
    """
    Comprehensive SSL/TLS security checker.
    """
    
    # Weak cipher patterns
    WEAK_CIPHERS = [
        'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'anon', 'ADH', 'AECDH'
    ]
    
    # Modern protocols
    MODERN_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']
    DEPRECATED_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def check(self, host: str, port: int = 443) -> SSLResult:
        """
        Perform comprehensive SSL/TLS check.
        
        Args:
            host: Hostname to check
            port: Port (default: 443)
            
        Returns:
            SSLResult
        """
        result = SSLResult(host=host, port=port)
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    result.connected = True
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Parse certificate
                    self._parse_certificate(cert, result)
                    
                    # Get protocol/cipher info
                    result.protocol_version = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        result.cipher_name = cipher[0]
                        result.cipher_bits = cipher[2]
                    
                    # Security assessment
                    self._assess_security(result)
                    
        except ssl.SSLCertVerificationError as e:
            result.error = f"Certificate verification failed: {e}"
            result.cert_chain_valid = False
            result.grade = 'F'
        except ssl.SSLError as e:
            result.error = f"SSL error: {e}"
            result.grade = 'F'
        except socket.timeout:
            result.error = "Connection timeout"
        except socket.gaierror as e:
            result.error = f"DNS resolution failed: {e}"
        except ConnectionRefusedError:
            result.error = "Connection refused"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _parse_certificate(self, cert: dict, result: SSLResult):
        """Parse certificate details."""
        # Subject
        subject = dict(x[0] for x in cert.get('subject', ()))
        result.cert_subject = {
            'common_name': subject.get('commonName', ''),
            'organization': subject.get('organizationName', ''),
            'country': subject.get('countryName', ''),
        }
        
        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        result.cert_issuer = {
            'common_name': issuer.get('commonName', ''),
            'organization': issuer.get('organizationName', ''),
            'country': issuer.get('countryName', ''),
        }
        
        # Dates
        result.not_before = cert.get('notBefore', '')
        result.not_after = cert.get('notAfter', '')
        
        # Calculate expiry
        if result.not_after:
            try:
                # Parse SSL date format
                expiry = datetime.strptime(result.not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                delta = expiry - now
                result.days_until_expiry = delta.days
                result.is_expired = delta.days < 0
                result.is_expiring_soon = 0 <= delta.days < 30
            except ValueError:
                pass
        
        # Serial number
        result.serial_number = hex(cert.get('serialNumber', 0))
        result.cert_version = cert.get('version', 0)
        
        # Subject Alternative Names
        for type_name, value in cert.get('subjectAltName', ()):
            if type_name == 'DNS':
                result.san.append(value)
    
    def _assess_security(self, result: SSLResult):
        """Assess security and calculate grade."""
        points = 100
        
        # Check protocol version
        if result.protocol_version in self.DEPRECATED_PROTOCOLS:
            result.warnings.append(f"Deprecated protocol: {result.protocol_version}")
            points -= 30
        elif result.protocol_version == 'TLSv1.2':
            points -= 5  # Slight penalty, TLS 1.3 preferred
        
        # Check cipher
        cipher_upper = result.cipher_name.upper()
        for weak in self.WEAK_CIPHERS:
            if weak in cipher_upper:
                result.vulnerabilities.append(f"Weak cipher: {result.cipher_name}")
                points -= 40
                break
        
        # Check key size
        if result.cipher_bits < 128:
            result.vulnerabilities.append(f"Weak key size: {result.cipher_bits} bits")
            points -= 30
        elif result.cipher_bits < 256:
            result.warnings.append(f"Consider stronger cipher ({result.cipher_bits} bits)")
            points -= 5
        
        # Check expiry
        if result.is_expired:
            result.vulnerabilities.append("Certificate is EXPIRED")
            points -= 50
        elif result.is_expiring_soon:
            result.warnings.append(f"Certificate expires in {result.days_until_expiry} days")
            points -= 10
        
        # Check chain validation
        if not result.cert_chain_valid:
            result.vulnerabilities.append("Certificate chain validation failed")
            points -= 50
        
        # Calculate grade
        if points >= 90:
            result.grade = 'A'
        elif points >= 80:
            result.grade = 'B'
        elif points >= 60:
            result.grade = 'C'
        elif points >= 40:
            result.grade = 'D'
        else:
            result.grade = 'F'
    
    def quick_check(self, host: str, port: int = 443) -> dict:
        """Quick check - returns simple pass/fail."""
        result = self.check(host, port)
        return {
            'host': host,
            'valid': result.connected and not result.is_expired and result.grade in ('A', 'B'),
            'grade': result.grade,
            'days_until_expiry': result.days_until_expiry,
            'protocol': result.protocol_version,
        }

