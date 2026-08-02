"""
WHOIS Lookup Client
Domain registration information lookups.
"""

from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

from ..cache import cache


@dataclass
class WHOISResult:
    """WHOIS lookup result."""
    domain: str
    found: bool = False
    
    # Registrar info
    registrar: str = ""
    registrar_url: str = ""
    registrar_abuse_email: str = ""
    registrar_abuse_phone: str = ""
    
    # Dates
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    
    # Domain status
    status: list = field(default_factory=list)
    
    # Nameservers
    nameservers: list = field(default_factory=list)
    
    # DNSSEC
    dnssec: str = ""
    
    # Registrant info (often redacted)
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    registrant_email: str = ""
    
    # Privacy
    privacy_protected: bool = False
    
    # Raw
    raw_text: str = ""
    error: str = ""
    
    @property
    def days_until_expiration(self) -> Optional[int]:
        """Calculate days until domain expires."""
        if not self.expiration_date:
            return None
        try:
            # Try common date formats
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%d-%b-%Y']:
                try:
                    exp_date = datetime.strptime(self.expiration_date[:19], fmt)
                    delta = exp_date - datetime.now()
                    return delta.days
                except ValueError:
                    continue
        except Exception:
            pass
        return None
    
    @property
    def domain_age_days(self) -> Optional[int]:
        """Calculate domain age in days."""
        if not self.creation_date:
            return None
        try:
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%d-%b-%Y']:
                try:
                    create_date = datetime.strptime(self.creation_date[:19], fmt)
                    delta = datetime.now() - create_date
                    return delta.days
                except ValueError:
                    continue
        except Exception:
            pass
        return None
    
    @property
    def is_newly_registered(self) -> bool:
        """Check if domain was registered recently (<30 days)."""
        age = self.domain_age_days
        return age is not None and age < 30
    
    @property
    def is_expiring_soon(self) -> bool:
        """Check if domain expires within 30 days."""
        days = self.days_until_expiration
        return days is not None and days < 30
    
    def to_dict(self) -> dict:
        return {
            'domain': self.domain,
            'found': self.found,
            'registrar': self.registrar,
            'registrar_url': self.registrar_url,
            'creation_date': self.creation_date,
            'expiration_date': self.expiration_date,
            'updated_date': self.updated_date,
            'domain_age_days': self.domain_age_days,
            'days_until_expiration': self.days_until_expiration,
            'is_newly_registered': self.is_newly_registered,
            'is_expiring_soon': self.is_expiring_soon,
            'status': self.status,
            'nameservers': self.nameservers,
            'dnssec': self.dnssec,
            'registrant_org': self.registrant_org,
            'registrant_country': self.registrant_country,
            'privacy_protected': self.privacy_protected,
            'error': self.error,
        }


class WHOISClient:
    """
    WHOIS lookup client.
    
    Uses python-whois library for lookups.
    """
    
    # Privacy service indicators
    PRIVACY_INDICATORS = [
        'whoisguard', 'privacy', 'protected', 'proxy', 'redacted',
        'domains by proxy', 'contact privacy', 'whois privacy',
        'domain privacy', 'private registration', 'withheld for privacy',
        'data protected', 'privacyprotect', 'whoisprivacy'
    ]
    
    def __init__(self):
        pass
    
    def lookup(self, domain: str, use_cache: bool = True) -> WHOISResult:
        """
        Look up WHOIS information for a domain.
        
        Args:
            domain: Domain to look up
            use_cache: Whether to use cache
            
        Returns:
            WHOISResult
        """
        result = WHOISResult(domain=domain)
        
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        
        result.domain = domain
        
        if use_cache:
            cached = cache.get('whois', domain)
            if cached:
                return WHOISResult(**cached)
        
        try:
            import whois
            
            w = whois.whois(domain)
            
            if not w.domain_name:
                result.found = False
                result.error = "Domain not found"
                return result
            
            result.found = True
            
            # Registrar
            result.registrar = w.registrar or ""
            
            # Dates (can be list or single value)
            def get_date(value):
                if isinstance(value, list):
                    value = value[0] if value else None
                if isinstance(value, datetime):
                    return value.isoformat()
                return str(value) if value else ""
            
            result.creation_date = get_date(w.creation_date)
            result.expiration_date = get_date(w.expiration_date)
            result.updated_date = get_date(w.updated_date)
            
            # Status
            if w.status:
                if isinstance(w.status, list):
                    result.status = w.status
                else:
                    result.status = [w.status]
            
            # Nameservers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result.nameservers = [ns.lower() for ns in w.name_servers]
                else:
                    result.nameservers = [w.name_servers.lower()]
            
            # DNSSEC
            result.dnssec = str(w.dnssec) if hasattr(w, 'dnssec') and w.dnssec else ""
            
            # Registrant info
            result.registrant_name = w.name or ""
            result.registrant_org = w.org or ""
            result.registrant_country = w.country or ""
            
            if hasattr(w, 'emails') and w.emails:
                if isinstance(w.emails, list):
                    result.registrant_email = w.emails[0]
                else:
                    result.registrant_email = w.emails
            
            # Check for privacy protection
            raw_lower = str(w.text).lower() if hasattr(w, 'text') else ""
            for indicator in self.PRIVACY_INDICATORS:
                if indicator in raw_lower:
                    result.privacy_protected = True
                    break
            
            if hasattr(w, 'text'):
                result.raw_text = w.text
            
            if use_cache:
                cache.set('whois', domain, result.to_dict(), ttl_hours=168)  # 7 days
            
        except ImportError:
            result.error = "python-whois library not installed. Install with: pip install python-whois"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def is_suspicious_domain(self, result: WHOISResult) -> dict:
        """
        Check if domain has suspicious characteristics.
        
        Args:
            result: WHOISResult from lookup
            
        Returns:
            Dict with suspicion flags and reasons
        """
        flags = {
            'is_suspicious': False,
            'reasons': [],
            'risk_score': 0
        }
        
        # Newly registered domains are often used for phishing
        if result.is_newly_registered:
            flags['reasons'].append(f"Domain registered only {result.domain_age_days} days ago")
            flags['risk_score'] += 30
        
        # Privacy protected could be suspicious
        if result.privacy_protected:
            flags['reasons'].append("WHOIS privacy protection enabled")
            flags['risk_score'] += 10
        
        # Expiring soon might indicate throwaway domain
        if result.is_expiring_soon:
            flags['reasons'].append(f"Domain expires in {result.days_until_expiration} days")
            flags['risk_score'] += 20
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link', '.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if result.domain.endswith(tld):
                flags['reasons'].append(f"Uses suspicious TLD: {tld}")
                flags['risk_score'] += 15
                break
        
        # Very short registration period
        if result.days_until_expiration and result.domain_age_days:
            total_registration = result.domain_age_days + result.days_until_expiration
            if total_registration < 365:  # Less than 1 year registration
                flags['reasons'].append("Short registration period (< 1 year)")
                flags['risk_score'] += 15
        
        flags['is_suspicious'] = flags['risk_score'] >= 30
        
        return flags

