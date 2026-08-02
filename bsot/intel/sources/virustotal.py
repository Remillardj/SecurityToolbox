"""
VirusTotal API Client
"""

import base64
import requests
from typing import Optional
from dataclasses import dataclass, field

from ...cache import cache, from_cached


@dataclass
class VTResult:
    """VirusTotal lookup result."""
    ioc: str
    ioc_type: str
    found: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    score: float = 0.0
    categories: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    permalink: str = ""
    raw: dict = field(default_factory=dict)
    error: str = ""
    
    @property
    def is_malicious(self) -> bool:
        return self.malicious >= 3
    
    @property
    def is_suspicious(self) -> bool:
        return self.malicious >= 1 or self.suspicious >= 2
    
    @property
    def detection_ratio(self) -> str:
        if self.total_engines > 0:
            return f"{self.malicious + self.suspicious}/{self.total_engines}"
        return "N/A"
    
    def to_dict(self) -> dict:
        return {
            'ioc': self.ioc,
            'ioc_type': self.ioc_type,
            'found': self.found,
            'malicious': self.malicious,
            'suspicious': self.suspicious,
            'harmless': self.harmless,
            'undetected': self.undetected,
            'total_engines': self.total_engines,
            'score': self.score,
            'detection_ratio': self.detection_ratio,
            'is_malicious': self.is_malicious,
            'is_suspicious': self.is_suspicious,
            'categories': self.categories,
            'tags': self.tags,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'permalink': self.permalink,
            'error': self.error,
        }


class VirusTotalClient:
    """Client for VirusTotal API v3."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    
    def _make_request(self, endpoint: str) -> Optional[dict]:
        """Make API request."""
        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return None
    
    def _parse_stats(self, data: dict) -> VTResult:
        """Parse analysis stats from response."""
        result = VTResult(ioc="", ioc_type="")
        
        if not data:
            return result
        
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        result.found = True
        result.malicious = stats.get('malicious', 0)
        result.suspicious = stats.get('suspicious', 0)
        result.harmless = stats.get('harmless', 0)
        result.undetected = stats.get('undetected', 0)
        result.total_engines = sum(stats.values())
        
        if result.total_engines > 0:
            result.score = (result.malicious + result.suspicious) / result.total_engines
        
        # Categories
        cats = attrs.get('categories', {})
        if isinstance(cats, dict):
            result.categories = list(set(cats.values()))
        
        # Tags
        result.tags = attrs.get('tags', [])
        
        # Timestamps
        result.first_seen = attrs.get('first_submission_date', '')
        result.last_seen = attrs.get('last_analysis_date', '')
        
        result.raw = data
        
        return result
    
    def lookup_ip(self, ip: str, use_cache: bool = True) -> VTResult:
        """Look up IP address."""
        if use_cache:
            cached = cache.get('virustotal', f"ip:{ip}")
            if cached:
                result = from_cached(VTResult, cached)
                result.ioc = ip
                result.ioc_type = 'ip'
                return result
        
        data = self._make_request(f"ip_addresses/{ip}")
        result = self._parse_stats(data)
        result.ioc = ip
        result.ioc_type = 'ip'
        
        if data:
            result.permalink = f"https://www.virustotal.com/gui/ip-address/{ip}"
            attrs = data.get('data', {}).get('attributes', {})
            result.tags.extend([
                f"country:{attrs.get('country', '')}",
                f"asn:{attrs.get('asn', '')}"
            ])
        
        if use_cache and result.found:
            cache.set('virustotal', f"ip:{ip}", result.to_dict())
        
        return result
    
    def lookup_domain(self, domain: str, use_cache: bool = True) -> VTResult:
        """Look up domain."""
        if use_cache:
            cached = cache.get('virustotal', f"domain:{domain}")
            if cached:
                result = from_cached(VTResult, cached)
                result.ioc = domain
                result.ioc_type = 'domain'
                return result
        
        data = self._make_request(f"domains/{domain}")
        result = self._parse_stats(data)
        result.ioc = domain
        result.ioc_type = 'domain'
        
        if data:
            result.permalink = f"https://www.virustotal.com/gui/domain/{domain}"
        
        if use_cache and result.found:
            cache.set('virustotal', f"domain:{domain}", result.to_dict())
        
        return result
    
    def lookup_url(self, url: str, use_cache: bool = True) -> VTResult:
        """Look up URL."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        
        if use_cache:
            cached = cache.get('virustotal', f"url:{url_id}")
            if cached:
                result = from_cached(VTResult, cached)
                result.ioc = url
                result.ioc_type = 'url'
                return result
        
        data = self._make_request(f"urls/{url_id}")
        result = self._parse_stats(data)
        result.ioc = url
        result.ioc_type = 'url'
        
        if data:
            result.permalink = f"https://www.virustotal.com/gui/url/{url_id}"
        
        if use_cache and result.found:
            cache.set('virustotal', f"url:{url_id}", result.to_dict())
        
        return result
    
    def lookup_hash(self, file_hash: str, use_cache: bool = True) -> VTResult:
        """Look up file hash."""
        if use_cache:
            cached = cache.get('virustotal', f"hash:{file_hash}")
            if cached:
                result = from_cached(VTResult, cached)
                result.ioc = file_hash
                result.ioc_type = 'hash'
                return result
        
        data = self._make_request(f"files/{file_hash}")
        result = self._parse_stats(data)
        result.ioc = file_hash
        result.ioc_type = 'hash'
        
        if data:
            result.permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
            attrs = data.get('data', {}).get('attributes', {})
            result.tags.extend(attrs.get('type_tags', []))
        
        if use_cache and result.found:
            cache.set('virustotal', f"hash:{file_hash}", result.to_dict())
        
        return result
    
    def lookup(self, ioc: str, ioc_type: str = None, use_cache: bool = True) -> VTResult:
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
            result = VTResult(ioc=ioc, ioc_type=ioc_type)
            result.error = f"Unsupported IOC type: {ioc_type}"
            return result

