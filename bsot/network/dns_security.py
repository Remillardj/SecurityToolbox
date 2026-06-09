"""
DNS Security Checker
Check DNS records and email authentication.
"""

import dns.resolver
import dns.exception
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class DNSResult:
    """DNS security check result."""
    domain: str
    
    # Basic records
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_record: str = ""
    
    # Email security
    spf_record: str = ""
    spf_valid: bool = False
    spf_policy: str = ""  # all, ~all, -all, ?all
    
    dmarc_record: str = ""
    dmarc_valid: bool = False
    dmarc_policy: str = ""  # none, quarantine, reject
    
    dkim_found: bool = False
    dkim_selectors: List[str] = field(default_factory=list)
    
    # Security records
    caa_records: List[str] = field(default_factory=list)
    dnssec: bool = False
    
    # Assessment
    email_security_grade: str = ""
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'domain': self.domain,
            'records': {
                'a': self.a_records,
                'aaaa': self.aaaa_records,
                'mx': self.mx_records,
                'ns': self.ns_records,
                'txt': self.txt_records,
                'cname': self.cname_record,
                'caa': self.caa_records,
            },
            'email_security': {
                'spf': {
                    'record': self.spf_record,
                    'valid': self.spf_valid,
                    'policy': self.spf_policy,
                },
                'dmarc': {
                    'record': self.dmarc_record,
                    'valid': self.dmarc_valid,
                    'policy': self.dmarc_policy,
                },
                'dkim': {
                    'found': self.dkim_found,
                    'selectors': self.dkim_selectors,
                },
            },
            'dnssec': self.dnssec,
            'email_security_grade': self.email_security_grade,
            'warnings': self.warnings,
            'recommendations': self.recommendations,
            'error': self.error,
        }


class DNSChecker:
    """
    DNS and email security checker.
    """
    
    # Common DKIM selectors to try
    COMMON_DKIM_SELECTORS = [
        'default', 'google', 'selector1', 'selector2',
        'mail', 'dkim', 'k1', 'k2', 's1', 's2',
        'mandrill', 'mailchimp', 'amazonses', 'sendgrid',
    ]
    
    def __init__(self, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def check(self, domain: str) -> DNSResult:
        """
        Perform comprehensive DNS security check.
        
        Args:
            domain: Domain to check
            
        Returns:
            DNSResult
        """
        result = DNSResult(domain=domain)
        
        # Get basic records
        result.a_records = self._query(domain, 'A')
        result.aaaa_records = self._query(domain, 'AAAA')
        result.ns_records = self._query(domain, 'NS')
        result.txt_records = self._query(domain, 'TXT')
        
        # CNAME
        cnames = self._query(domain, 'CNAME')
        if cnames:
            result.cname_record = cnames[0]
        
        # MX records with priority
        try:
            mx_answers = self.resolver.resolve(domain, 'MX')
            for rdata in mx_answers:
                result.mx_records.append({
                    'priority': rdata.preference,
                    'host': str(rdata.exchange).rstrip('.')
                })
            result.mx_records.sort(key=lambda x: x['priority'])
        except Exception:
            pass
        
        # CAA records
        result.caa_records = self._query(domain, 'CAA')
        
        # Check email security
        self._check_spf(domain, result)
        self._check_dmarc(domain, result)
        self._check_dkim(domain, result)
        
        # Check DNSSEC
        result.dnssec = self._check_dnssec(domain)
        
        # Assess email security
        self._assess_email_security(result)
        
        return result
    
    def _query(self, domain: str, record_type: str) -> List[str]:
        """Query DNS records."""
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata).strip('"') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []
    
    def _check_spf(self, domain: str, result: DNSResult):
        """Check SPF record."""
        for txt in result.txt_records:
            if txt.lower().startswith('v=spf1'):
                result.spf_record = txt
                result.spf_valid = True
                
                # Extract policy
                if ' -all' in txt.lower():
                    result.spf_policy = 'fail'  # -all (hard fail)
                elif ' ~all' in txt.lower():
                    result.spf_policy = 'softfail'  # ~all
                elif ' ?all' in txt.lower():
                    result.spf_policy = 'neutral'  # ?all
                elif ' +all' in txt.lower():
                    result.spf_policy = 'pass'  # +all (dangerous!)
                    result.warnings.append("SPF with +all allows any sender (dangerous)")
                
                break
        
        if not result.spf_record:
            result.recommendations.append("Add SPF record to prevent email spoofing")
    
    def _check_dmarc(self, domain: str, result: DNSResult):
        """Check DMARC record."""
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = self._query(dmarc_domain, 'TXT')
        
        for txt in dmarc_records:
            if txt.lower().startswith('v=dmarc1'):
                result.dmarc_record = txt
                result.dmarc_valid = True
                
                # Extract policy
                if 'p=reject' in txt.lower():
                    result.dmarc_policy = 'reject'
                elif 'p=quarantine' in txt.lower():
                    result.dmarc_policy = 'quarantine'
                elif 'p=none' in txt.lower():
                    result.dmarc_policy = 'none'
                    result.warnings.append("DMARC policy is 'none' - emails won't be blocked")
                
                break
        
        if not result.dmarc_record:
            result.recommendations.append("Add DMARC record to control email handling")
    
    def _check_dkim(self, domain: str, result: DNSResult):
        """Check for DKIM records."""
        for selector in self.COMMON_DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = self._query(dkim_domain, 'TXT')
            
            for txt in dkim_records:
                if 'v=dkim1' in txt.lower() or 'p=' in txt.lower():
                    result.dkim_found = True
                    result.dkim_selectors.append(selector)
                    break
            
            # Also try CNAME (common for hosted services)
            cnames = self._query(dkim_domain, 'CNAME')
            if cnames:
                result.dkim_found = True
                result.dkim_selectors.append(f"{selector} (CNAME)")
        
        if not result.dkim_found:
            result.recommendations.append("Consider adding DKIM for email authentication")
    
    def _check_dnssec(self, domain: str) -> bool:
        """Check if DNSSEC is enabled."""
        try:
            # Try to get DNSKEY record
            self.resolver.resolve(domain, 'DNSKEY')
            return True
        except Exception:
            return False
    
    def _assess_email_security(self, result: DNSResult):
        """Calculate email security grade."""
        score = 0
        
        # SPF
        if result.spf_valid:
            score += 30
            if result.spf_policy == 'fail':
                score += 10
            elif result.spf_policy == 'softfail':
                score += 5
        
        # DMARC
        if result.dmarc_valid:
            score += 30
            if result.dmarc_policy == 'reject':
                score += 15
            elif result.dmarc_policy == 'quarantine':
                score += 10
        
        # DKIM
        if result.dkim_found:
            score += 20
        
        # DNSSEC
        if result.dnssec:
            score += 5
        
        # Calculate grade
        if score >= 90:
            result.email_security_grade = 'A'
        elif score >= 75:
            result.email_security_grade = 'B'
        elif score >= 50:
            result.email_security_grade = 'C'
        elif score >= 25:
            result.email_security_grade = 'D'
        else:
            result.email_security_grade = 'F'
    
    def lookup(self, domain: str, record_type: str = 'A') -> List[str]:
        """Simple DNS lookup."""
        return self._query(domain, record_type.upper())
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            from dns.reversename import from_address
            rev_name = from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            return str(answers[0]).rstrip('.')
        except Exception:
            return None

