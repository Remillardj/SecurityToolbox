"""
AlienVault OTX (Open Threat Exchange) API Client
"""

import requests
from typing import Optional
from dataclasses import dataclass, field

from ...cache import cache


@dataclass
class OTXResult:
    """OTX lookup result."""
    ioc: str
    ioc_type: str
    found: bool = False
    pulse_count: int = 0
    pulses: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    malware_families: list = field(default_factory=list)
    adversaries: list = field(default_factory=list)
    # For IPs
    country: str = ""
    asn: str = ""
    # For domains
    alexa_rank: int = 0
    whois: dict = field(default_factory=dict)
    # Passive DNS
    passive_dns: list = field(default_factory=list)
    # URLs
    url_list: list = field(default_factory=list)
    # General
    validation: list = field(default_factory=list)
    sections: list = field(default_factory=list)
    error: str = ""
    raw: dict = field(default_factory=dict)
    
    @property
    def is_malicious(self) -> bool:
        return self.pulse_count >= 5
    
    @property
    def is_suspicious(self) -> bool:
        return self.pulse_count >= 1
    
    @property
    def score(self) -> float:
        if self.pulse_count >= 10:
            return 0.9
        elif self.pulse_count >= 5:
            return 0.7
        elif self.pulse_count >= 1:
            return 0.4
        return 0.0
    
    def to_dict(self) -> dict:
        return {
            'ioc': self.ioc,
            'ioc_type': self.ioc_type,
            'found': self.found,
            'pulse_count': self.pulse_count,
            'pulses': self.pulses[:5],  # Limit for readability
            'tags': self.tags,
            'malware_families': self.malware_families,
            'adversaries': self.adversaries,
            'country': self.country,
            'asn': self.asn,
            'alexa_rank': self.alexa_rank,
            'passive_dns': self.passive_dns[:10],
            'is_malicious': self.is_malicious,
            'is_suspicious': self.is_suspicious,
            'score': self.score,
            'error': self.error,
        }


class OTXClient:
    """Client for AlienVault OTX API."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }
    
    def _get(self, endpoint: str) -> Optional[dict]:
        """Make GET request to OTX API."""
        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
        except requests.exceptions.RequestException:
            pass
        return None
    
    def lookup_ip(self, ip: str, use_cache: bool = True) -> OTXResult:
        """Look up IP address."""
        result = OTXResult(ioc=ip, ioc_type='ip')
        
        if use_cache:
            cached = cache.get('otx', f"ip:{ip}")
            if cached:
                return OTXResult(**cached)
        
        # Get general info
        general = self._get(f"indicators/IPv4/{ip}/general")
        if general:
            result.found = True
            result.pulse_count = general.get('pulse_info', {}).get('count', 0)
            result.pulses = [
                {'name': p.get('name'), 'id': p.get('id')}
                for p in general.get('pulse_info', {}).get('pulses', [])[:10]
            ]
            result.validation = general.get('validation', [])
            result.sections = general.get('sections', [])
            result.country = general.get('country_name', '')
            result.asn = general.get('asn', '')
            
            # Extract tags from pulses
            for pulse in general.get('pulse_info', {}).get('pulses', []):
                result.tags.extend(pulse.get('tags', []))
                if pulse.get('malware_families'):
                    result.malware_families.extend(pulse.get('malware_families'))
                if pulse.get('adversary'):
                    result.adversaries.append(pulse.get('adversary'))
            
            result.tags = list(set(result.tags))
            result.malware_families = list(set(result.malware_families))
            result.adversaries = list(set(result.adversaries))
        
        # Get passive DNS
        pdns = self._get(f"indicators/IPv4/{ip}/passive_dns")
        if pdns:
            result.passive_dns = [
                {'hostname': r.get('hostname'), 'last': r.get('last')}
                for r in pdns.get('passive_dns', [])[:20]
            ]
        
        if use_cache and result.found:
            cache.set('otx', f"ip:{ip}", result.to_dict())
        
        return result
    
    def lookup_domain(self, domain: str, use_cache: bool = True) -> OTXResult:
        """Look up domain."""
        result = OTXResult(ioc=domain, ioc_type='domain')
        
        if use_cache:
            cached = cache.get('otx', f"domain:{domain}")
            if cached:
                return OTXResult(**cached)
        
        # Get general info
        general = self._get(f"indicators/domain/{domain}/general")
        if general:
            result.found = True
            result.pulse_count = general.get('pulse_info', {}).get('count', 0)
            result.pulses = [
                {'name': p.get('name'), 'id': p.get('id')}
                for p in general.get('pulse_info', {}).get('pulses', [])[:10]
            ]
            result.validation = general.get('validation', [])
            result.alexa_rank = general.get('alexa', 0)
            result.whois = general.get('whois', {})
            
            for pulse in general.get('pulse_info', {}).get('pulses', []):
                result.tags.extend(pulse.get('tags', []))
                if pulse.get('malware_families'):
                    result.malware_families.extend(pulse.get('malware_families'))
            
            result.tags = list(set(result.tags))
            result.malware_families = list(set(result.malware_families))
        
        # Get passive DNS
        pdns = self._get(f"indicators/domain/{domain}/passive_dns")
        if pdns:
            result.passive_dns = [
                {'address': r.get('address'), 'last': r.get('last'), 'record_type': r.get('record_type')}
                for r in pdns.get('passive_dns', [])[:20]
            ]
        
        if use_cache and result.found:
            cache.set('otx', f"domain:{domain}", result.to_dict())
        
        return result
    
    def lookup_hash(self, file_hash: str, use_cache: bool = True) -> OTXResult:
        """Look up file hash."""
        result = OTXResult(ioc=file_hash, ioc_type='hash')
        
        if use_cache:
            cached = cache.get('otx', f"hash:{file_hash}")
            if cached:
                return OTXResult(**cached)
        
        general = self._get(f"indicators/file/{file_hash}/general")
        if general:
            result.found = True
            result.pulse_count = general.get('pulse_info', {}).get('count', 0)
            result.pulses = [
                {'name': p.get('name'), 'id': p.get('id')}
                for p in general.get('pulse_info', {}).get('pulses', [])[:10]
            ]
            
            for pulse in general.get('pulse_info', {}).get('pulses', []):
                result.tags.extend(pulse.get('tags', []))
                if pulse.get('malware_families'):
                    result.malware_families.extend(pulse.get('malware_families'))
            
            result.tags = list(set(result.tags))
            result.malware_families = list(set(result.malware_families))
        
        if use_cache and result.found:
            cache.set('otx', f"hash:{file_hash}", result.to_dict())
        
        return result
    
    def lookup_url(self, url: str, use_cache: bool = True) -> OTXResult:
        """Look up URL."""
        result = OTXResult(ioc=url, ioc_type='url')
        
        # URL needs to be base64 encoded for API
        import base64
        url_encoded = base64.b64encode(url.encode()).decode()
        
        if use_cache:
            cached = cache.get('otx', f"url:{url_encoded[:32]}")
            if cached:
                return OTXResult(**cached)
        
        general = self._get(f"indicators/url/{url_encoded}/general")
        if general:
            result.found = True
            result.pulse_count = general.get('pulse_info', {}).get('count', 0)
            result.pulses = [
                {'name': p.get('name'), 'id': p.get('id')}
                for p in general.get('pulse_info', {}).get('pulses', [])[:10]
            ]
            
            for pulse in general.get('pulse_info', {}).get('pulses', []):
                result.tags.extend(pulse.get('tags', []))
            result.tags = list(set(result.tags))
        
        if use_cache and result.found:
            cache.set('otx', f"url:{url_encoded[:32]}", result.to_dict())
        
        return result
    
    def lookup(self, ioc: str, ioc_type: str = None, use_cache: bool = True) -> OTXResult:
        """Generic lookup - auto-detect type if not specified."""
        from ..ioc_utils import detect_ioc_type
        
        if not ioc_type:
            detected = detect_ioc_type(ioc)
            ioc_type = detected.value
        
        if ioc_type in ('ipv4', 'ipv6', 'ip'):
            return self.lookup_ip(ioc, use_cache)
        elif ioc_type == 'domain':
            return self.lookup_domain(ioc, use_cache)
        elif ioc_type == 'url':
            return self.lookup_url(ioc, use_cache)
        elif ioc_type in ('md5', 'sha1', 'sha256', 'sha512', 'hash'):
            return self.lookup_hash(ioc, use_cache)
        else:
            result = OTXResult(ioc=ioc, ioc_type=ioc_type)
            result.error = f"Unsupported IOC type: {ioc_type}"
            return result

