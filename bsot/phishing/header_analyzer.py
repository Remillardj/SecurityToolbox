"""
Email Header Analyzer Module
Analyzes email headers for authentication and security issues.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AuthenticationResult:
    """Result of an authentication check."""
    mechanism: str  # SPF, DKIM, DMARC
    result: str     # pass, fail, softfail, neutral, none, etc.
    details: str = ""
    domain: str = ""
    selector: str = ""  # For DKIM


@dataclass
class ReceivedHop:
    """Represents a single hop in the email routing path."""
    from_server: str = ""
    by_server: str = ""
    with_protocol: str = ""
    timestamp: Optional[datetime] = None
    delay_seconds: int = 0
    ip_address: str = ""
    ptr_record: str = ""


@dataclass 
class HeaderAnalysisResult:
    """Complete header analysis results."""
    # Authentication
    spf_result: Optional[AuthenticationResult] = None
    dkim_result: Optional[AuthenticationResult] = None
    dmarc_result: Optional[AuthenticationResult] = None
    arc_result: Optional[AuthenticationResult] = None
    
    # Routing
    received_hops: List[ReceivedHop] = field(default_factory=list)
    total_transit_time: int = 0
    
    # Sender analysis
    envelope_from: str = ""
    header_from: str = ""
    reply_to: str = ""
    return_path: str = ""
    from_domain_mismatch: bool = False
    
    # Security indicators
    warnings: List[str] = field(default_factory=list)
    suspicious_indicators: List[str] = field(default_factory=list)
    
    # Raw data
    x_headers: Dict[str, str] = field(default_factory=dict)
    
    @property
    def auth_score(self) -> int:
        """Calculate authentication score (0-100)."""
        score = 0
        
        if self.spf_result and self.spf_result.result == 'pass':
            score += 35
        elif self.spf_result and self.spf_result.result == 'softfail':
            score += 15
            
        if self.dkim_result and self.dkim_result.result == 'pass':
            score += 35
            
        if self.dmarc_result and self.dmarc_result.result == 'pass':
            score += 30
        elif self.dmarc_result and self.dmarc_result.result in ('bestguess', 'none'):
            score += 10
        
        return min(score, 100)
    
    @property
    def is_authenticated(self) -> bool:
        """Check if email passes basic authentication."""
        spf_ok = self.spf_result and self.spf_result.result in ('pass', 'softfail')
        dkim_ok = self.dkim_result and self.dkim_result.result == 'pass'
        dmarc_ok = self.dmarc_result and self.dmarc_result.result == 'pass'
        
        return (spf_ok and dkim_ok) or dmarc_ok


class HeaderAnalyzer:
    """
    Analyzes email headers for authentication, routing, and security issues.
    """
    
    # Suspicious header patterns
    SUSPICIOUS_PATTERNS = [
        (r'X-Spam-Flag:\s*YES', 'Email flagged as spam'),
        (r'X-Spam-Score:\s*[5-9]|X-Spam-Score:\s*\d{2,}', 'High spam score'),
        (r'X-Virus-Scanned', None),  # Informational
        (r'X-Originating-IP', None),  # Extract for analysis
    ]
    
    # Known suspicious mail servers
    SUSPICIOUS_SERVERS = [
        'mail-relay', 'smtp-out', 'bulk', 'mass-mail',
    ]
    
    def __init__(self):
        self.dns_cache = {}
    
    def analyze(self, headers: Dict[str, List[str]], raw_headers: str = "") -> HeaderAnalysisResult:
        """
        Perform comprehensive header analysis.
        
        Args:
            headers: Dictionary of header name -> list of values
            raw_headers: Raw header string for parsing
            
        Returns:
            HeaderAnalysisResult with all findings
        """
        result = HeaderAnalysisResult()
        
        # Parse authentication results
        auth_results = headers.get('Authentication-Results', [])
        if auth_results:
            result.spf_result = self._parse_spf_from_auth(auth_results[0])
            result.dkim_result = self._parse_dkim_from_auth(auth_results[0])
            result.dmarc_result = self._parse_dmarc_from_auth(auth_results[0])
        
        # Parse Received-SPF header if Authentication-Results doesn't have it
        if not result.spf_result:
            received_spf = headers.get('Received-SPF', [])
            if received_spf:
                result.spf_result = self._parse_received_spf(received_spf[0])
        
        # Parse DKIM-Signature header
        dkim_sig = headers.get('DKIM-Signature', [])
        if dkim_sig and not result.dkim_result:
            result.dkim_result = self._parse_dkim_signature(dkim_sig[0])
        
        # Parse ARC headers
        arc_auth = headers.get('ARC-Authentication-Results', [])
        if arc_auth:
            result.arc_result = self._parse_arc(arc_auth[0])
        
        # Parse Received headers (routing path)
        received = headers.get('Received', [])
        result.received_hops = self._parse_received_headers(received)
        
        # Calculate total transit time
        if len(result.received_hops) >= 2:
            result.total_transit_time = sum(hop.delay_seconds for hop in result.received_hops)
        
        # Extract sender information
        result.envelope_from = self._extract_address(
            headers.get('Return-Path', [''])[0] or 
            headers.get('Envelope-From', [''])[0]
        )
        result.header_from = self._extract_address(headers.get('From', [''])[0])
        result.reply_to = self._extract_address(headers.get('Reply-To', [''])[0])
        result.return_path = self._extract_address(headers.get('Return-Path', [''])[0])
        
        # Check for From domain mismatch
        result.from_domain_mismatch = self._check_domain_mismatch(
            result.envelope_from, result.header_from
        )
        
        # Extract X-headers
        for key, values in headers.items():
            if key.lower().startswith('x-'):
                result.x_headers[key] = values[0] if values else ""
        
        # Analyze for suspicious indicators
        result.warnings, result.suspicious_indicators = self._analyze_suspicious(
            headers, raw_headers, result
        )
        
        return result
    
    def _parse_spf_from_auth(self, auth_results: str) -> Optional[AuthenticationResult]:
        """Parse SPF result from Authentication-Results header."""
        # Pattern: spf=pass (or fail, softfail, etc.)
        match = re.search(
            r'spf=(\w+)(?:\s+\([^)]*\))?(?:\s+smtp\.(?:mailfrom|helo)=([^\s;]+))?',
            auth_results, 
            re.IGNORECASE
        )
        if match:
            return AuthenticationResult(
                mechanism='SPF',
                result=match.group(1).lower(),
                domain=match.group(2) or "",
                details=match.group(0)
            )
        return None
    
    def _parse_dkim_from_auth(self, auth_results: str) -> Optional[AuthenticationResult]:
        """Parse DKIM result from Authentication-Results header."""
        match = re.search(
            r'dkim=(\w+)(?:\s+\([^)]*\))?(?:\s+header\.(?:d|i|s)=([^\s;]+))?',
            auth_results,
            re.IGNORECASE
        )
        if match:
            return AuthenticationResult(
                mechanism='DKIM',
                result=match.group(1).lower(),
                domain=match.group(2) or "",
                details=match.group(0)
            )
        return None
    
    def _parse_dmarc_from_auth(self, auth_results: str) -> Optional[AuthenticationResult]:
        """Parse DMARC result from Authentication-Results header."""
        match = re.search(
            r'dmarc=(\w+)(?:\s+\([^)]*\))?(?:\s+header\.from=([^\s;]+))?',
            auth_results,
            re.IGNORECASE
        )
        if match:
            return AuthenticationResult(
                mechanism='DMARC',
                result=match.group(1).lower(),
                domain=match.group(2) or "",
                details=match.group(0)
            )
        return None
    
    def _parse_received_spf(self, received_spf: str) -> Optional[AuthenticationResult]:
        """Parse Received-SPF header."""
        # Format: pass (domain: example.com...) or fail ...
        match = re.match(r'^(\w+)\s+\(([^)]+)\)', received_spf)
        if match:
            return AuthenticationResult(
                mechanism='SPF',
                result=match.group(1).lower(),
                details=match.group(2)
            )
        
        # Simple format
        result = received_spf.split()[0].lower() if received_spf else None
        if result:
            return AuthenticationResult(
                mechanism='SPF',
                result=result,
                details=received_spf
            )
        return None
    
    def _parse_dkim_signature(self, dkim_sig: str) -> Optional[AuthenticationResult]:
        """Parse DKIM-Signature header."""
        domain_match = re.search(r'd=([^;\s]+)', dkim_sig)
        selector_match = re.search(r's=([^;\s]+)', dkim_sig)
        
        if domain_match:
            return AuthenticationResult(
                mechanism='DKIM',
                result='present',  # Signature exists, verification status unknown
                domain=domain_match.group(1),
                selector=selector_match.group(1) if selector_match else "",
                details="DKIM signature present (verification requires DNS lookup)"
            )
        return None
    
    def _parse_arc(self, arc_auth: str) -> Optional[AuthenticationResult]:
        """Parse ARC-Authentication-Results header."""
        # Similar to Authentication-Results
        arc_match = re.search(r'arc=(\w+)', arc_auth, re.IGNORECASE)
        if arc_match:
            return AuthenticationResult(
                mechanism='ARC',
                result=arc_match.group(1).lower(),
                details=arc_auth[:100]
            )
        return None
    
    def _parse_received_headers(self, received_headers: List[str]) -> List[ReceivedHop]:
        """Parse Received headers to extract routing information."""
        hops = []
        
        for i, received in enumerate(received_headers):
            hop = ReceivedHop()
            
            # Parse "from" server
            from_match = re.search(r'from\s+([^\s]+)', received, re.IGNORECASE)
            if from_match:
                hop.from_server = from_match.group(1)
            
            # Parse "by" server
            by_match = re.search(r'by\s+([^\s]+)', received, re.IGNORECASE)
            if by_match:
                hop.by_server = by_match.group(1)
            
            # Parse protocol (with ESMTP, SMTP, etc.)
            with_match = re.search(r'with\s+(\w+)', received, re.IGNORECASE)
            if with_match:
                hop.with_protocol = with_match.group(1)
            
            # Extract IP address
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
            if ip_match:
                hop.ip_address = ip_match.group(1)
            
            # Parse timestamp
            # Common formats: "Thu, 25 Dec 2025 10:30:00 -0500", etc.
            date_match = re.search(
                r';\s*(.+?)(?:\s*\([^)]*\))?$',
                received
            )
            if date_match:
                try:
                    from email.utils import parsedate_to_datetime
                    hop.timestamp = parsedate_to_datetime(date_match.group(1).strip())
                except Exception:
                    pass
            
            hops.append(hop)
        
        # Calculate delays between hops
        for i in range(len(hops) - 1):
            if hops[i].timestamp and hops[i + 1].timestamp:
                delay = (hops[i].timestamp - hops[i + 1].timestamp).total_seconds()
                hops[i].delay_seconds = max(0, int(delay))
        
        return hops
    
    def _extract_address(self, header_value: str) -> str:
        """Extract email address from header value."""
        if not header_value:
            return ""
        
        # Check for angle bracket format: Name <email@domain.com>
        match = re.search(r'<([^>]+)>', header_value)
        if match:
            return match.group(1).lower()
        
        # Check for plain email
        match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', header_value)
        if match:
            return match.group(0).lower()
        
        return header_value.strip().lower()
    
    def _check_domain_mismatch(self, envelope_from: str, header_from: str) -> bool:
        """Check if envelope and header From domains differ."""
        if not envelope_from or not header_from:
            return False
        
        def get_domain(email: str) -> str:
            if '@' in email:
                return email.split('@')[1].lower()
            return ""
        
        envelope_domain = get_domain(envelope_from)
        header_domain = get_domain(header_from)
        
        if not envelope_domain or not header_domain:
            return False
        
        return envelope_domain != header_domain
    
    def _analyze_suspicious(
        self, 
        headers: Dict[str, List[str]], 
        raw_headers: str,
        result: HeaderAnalysisResult
    ) -> Tuple[List[str], List[str]]:
        """Analyze headers for suspicious indicators."""
        warnings = []
        suspicious = []
        
        # Check authentication failures
        if result.spf_result:
            if result.spf_result.result == 'fail':
                suspicious.append("SPF check failed - sender not authorized")
            elif result.spf_result.result == 'softfail':
                warnings.append("SPF softfail - sender may not be authorized")
            elif result.spf_result.result == 'none':
                warnings.append("No SPF record found for sender domain")
        
        if result.dkim_result:
            if result.dkim_result.result == 'fail':
                suspicious.append("DKIM signature verification failed")
            elif result.dkim_result.result == 'none':
                warnings.append("No DKIM signature present")
        
        if result.dmarc_result:
            if result.dmarc_result.result == 'fail':
                suspicious.append("DMARC check failed - potential spoofing")
            elif result.dmarc_result.result == 'none':
                warnings.append("No DMARC policy for sender domain")
        
        # Check From domain mismatch
        if result.from_domain_mismatch:
            suspicious.append(
                f"From domain mismatch: envelope={result.envelope_from}, "
                f"header={result.header_from}"
            )
        
        # Check Reply-To mismatch
        if result.reply_to and result.header_from:
            reply_domain = result.reply_to.split('@')[1] if '@' in result.reply_to else ""
            from_domain = result.header_from.split('@')[1] if '@' in result.header_from else ""
            if reply_domain and from_domain and reply_domain != from_domain:
                suspicious.append(
                    f"Reply-To domain differs from From domain: "
                    f"reply={reply_domain}, from={from_domain}"
                )
        
        # Check for suspicious X-headers
        spam_flag = headers.get('X-Spam-Flag', [''])[0]
        if spam_flag.upper() == 'YES':
            suspicious.append("Email flagged as spam by mail server")
        
        spam_score = headers.get('X-Spam-Score', [''])[0]
        if spam_score:
            try:
                score = float(spam_score.replace('*', ''))
                if score >= 5:
                    suspicious.append(f"High spam score: {score}")
            except ValueError:
                pass
        
        # Check for excessive hops (potential relay abuse)
        if len(result.received_hops) > 10:
            warnings.append(f"Unusual number of mail hops: {len(result.received_hops)}")
        
        # Check for long transit time (potential queuing/delayed delivery)
        if result.total_transit_time > 3600:  # More than 1 hour
            warnings.append(
                f"Long transit time: {result.total_transit_time // 60} minutes"
            )
        
        # Check for missing critical headers
        if not headers.get('Message-ID'):
            warnings.append("Missing Message-ID header")
        
        if not headers.get('Date'):
            warnings.append("Missing Date header")
        
        return warnings, suspicious


def analyze_email_headers(parsed_email) -> HeaderAnalysisResult:
    """
    Convenience function to analyze headers from a ParsedEmail object.
    
    Args:
        parsed_email: A ParsedEmail object from email_parser module
        
    Returns:
        HeaderAnalysisResult object
    """
    analyzer = HeaderAnalyzer()
    return analyzer.analyze(parsed_email.headers, parsed_email.raw_headers)

