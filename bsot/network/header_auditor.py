"""
HTTP Security Header Auditor
Check for security headers on web servers.
"""

import requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class HeaderResult:
    """Security header audit result."""
    url: str
    status_code: int = 0
    
    # Headers found
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Security headers status
    security_headers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Overall assessment
    grade: str = ""  # A, B, C, D, F
    score: int = 0
    
    # Issues
    missing: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'url': self.url,
            'status_code': self.status_code,
            'grade': self.grade,
            'score': self.score,
            'security_headers': self.security_headers,
            'missing': self.missing,
            'warnings': self.warnings,
            'recommendations': self.recommendations,
            'error': self.error,
        }


class SecurityHeaderAuditor:
    """
    Audits HTTP security headers.
    
    Checks:
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    """
    
    # Security headers to check (name, importance, recommendations)
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'importance': 'critical',
            'points': 20,
            'recommend': 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'check_value': lambda v: 'max-age' in v.lower() and int(v.split('max-age=')[1].split(';')[0].split(',')[0]) >= 31536000,
        },
        'Content-Security-Policy': {
            'importance': 'high',
            'points': 20,
            'recommend': 'Add CSP header to prevent XSS attacks',
            'check_value': lambda v: len(v) > 10,  # Basic check
        },
        'X-Frame-Options': {
            'importance': 'medium',
            'points': 10,
            'recommend': 'Add X-Frame-Options: DENY or SAMEORIGIN',
            'check_value': lambda v: v.upper() in ['DENY', 'SAMEORIGIN'],
        },
        'X-Content-Type-Options': {
            'importance': 'medium',
            'points': 10,
            'recommend': 'Add X-Content-Type-Options: nosniff',
            'check_value': lambda v: v.lower() == 'nosniff',
        },
        'X-XSS-Protection': {
            'importance': 'low',
            'points': 5,
            'recommend': 'Add X-XSS-Protection: 1; mode=block (Note: deprecated in modern browsers)',
            'check_value': lambda v: '1' in v,
        },
        'Referrer-Policy': {
            'importance': 'medium',
            'points': 10,
            'recommend': 'Add Referrer-Policy: strict-origin-when-cross-origin',
            'check_value': lambda v: v.lower() in ['no-referrer', 'same-origin', 'strict-origin', 
                                                    'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'],
        },
        'Permissions-Policy': {
            'importance': 'medium',
            'points': 10,
            'recommend': 'Add Permissions-Policy to control browser features',
            'check_value': lambda v: len(v) > 5,
        },
        'Cross-Origin-Opener-Policy': {
            'importance': 'low',
            'points': 5,
            'recommend': 'Add Cross-Origin-Opener-Policy: same-origin',
            'check_value': lambda v: v.lower() in ['same-origin', 'same-origin-allow-popups'],
        },
        'Cross-Origin-Resource-Policy': {
            'importance': 'low',
            'points': 5,
            'recommend': 'Add Cross-Origin-Resource-Policy: same-origin',
            'check_value': lambda v: v.lower() in ['same-origin', 'same-site', 'cross-origin'],
        },
        'Cross-Origin-Embedder-Policy': {
            'importance': 'low',
            'points': 5,
            'recommend': 'Add Cross-Origin-Embedder-Policy: require-corp',
            'check_value': lambda v: v.lower() in ['require-corp', 'credentialless'],
        },
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def audit(self, url: str, follow_redirects: bool = True) -> HeaderResult:
        """
        Audit security headers for a URL.
        
        Args:
            url: URL to audit
            follow_redirects: Follow HTTP redirects
            
        Returns:
            HeaderResult
        """
        result = HeaderResult(url=url)
        
        # Ensure URL has scheme
        if not url.startswith('http'):
            url = f'https://{url}'
            result.url = url
        
        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                allow_redirects=follow_redirects,
                verify=True,
                headers={'User-Agent': 'BSOT Security Auditor'}
            )
            
            result.status_code = response.status_code
            result.headers = dict(response.headers)
            
            # Check each security header
            total_points = 0
            max_points = 0
            
            for header_name, config in self.SECURITY_HEADERS.items():
                max_points += config['points']
                header_status = {
                    'present': False,
                    'value': '',
                    'valid': False,
                    'importance': config['importance'],
                }
                
                # Case-insensitive header lookup
                value = None
                for key in response.headers:
                    if key.lower() == header_name.lower():
                        value = response.headers[key]
                        break
                
                if value:
                    header_status['present'] = True
                    header_status['value'] = value
                    
                    # Check value quality
                    try:
                        header_status['valid'] = config['check_value'](value)
                        if header_status['valid']:
                            total_points += config['points']
                        else:
                            result.warnings.append(f"{header_name} value may be weak: {value[:50]}")
                            total_points += config['points'] // 2
                    except Exception:
                        header_status['valid'] = True
                        total_points += config['points']
                else:
                    result.missing.append(header_name)
                    result.recommendations.append(config['recommend'])
                
                result.security_headers[header_name] = header_status
            
            # Calculate score and grade
            result.score = int((total_points / max_points) * 100) if max_points > 0 else 0
            
            if result.score >= 90:
                result.grade = 'A'
            elif result.score >= 75:
                result.grade = 'B'
            elif result.score >= 50:
                result.grade = 'C'
            elif result.score >= 25:
                result.grade = 'D'
            else:
                result.grade = 'F'
            
            # Check for dangerous headers that should not be present
            self._check_dangerous_headers(response.headers, result)
            
        except requests.exceptions.SSLError as e:
            result.error = f"SSL error: {e}"
        except requests.exceptions.ConnectionError as e:
            result.error = f"Connection error: {e}"
        except requests.exceptions.Timeout:
            result.error = "Request timeout"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _check_dangerous_headers(self, headers: dict, result: HeaderResult):
        """Check for headers that shouldn't be exposed."""
        dangerous = {
            'Server': 'Server header exposes web server version',
            'X-Powered-By': 'X-Powered-By exposes technology stack',
            'X-AspNet-Version': 'ASP.NET version exposed',
            'X-AspNetMvc-Version': 'ASP.NET MVC version exposed',
        }
        
        for header, warning in dangerous.items():
            if header in headers:
                result.warnings.append(f"{warning}: {headers[header]}")
    
    def get_header_value(self, url: str, header_name: str) -> Optional[str]:
        """Get a specific header value."""
        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
            return response.headers.get(header_name)
        except Exception:
            return None

