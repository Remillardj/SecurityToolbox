"""
GreyNoise API Client
"""

import requests
from typing import Optional
from dataclasses import dataclass, field

from ...cache import cache, from_cached


@dataclass
class GreyNoiseResult:
    """GreyNoise lookup result."""
    ip: str
    found: bool = False
    seen: bool = False
    classification: str = ""  # benign, malicious, unknown
    noise: bool = False
    riot: bool = False  # Rule It Out Test (known good)
    name: str = ""
    link: str = ""
    last_seen: str = ""
    first_seen: str = ""
    actor: str = ""
    tags: list = field(default_factory=list)
    cve: list = field(default_factory=list)
    vpn: bool = False
    vpn_service: str = ""
    bot: bool = False
    metadata: dict = field(default_factory=dict)
    error: str = ""
    raw: dict = field(default_factory=dict)
    
    @property
    def is_malicious(self) -> bool:
        return self.classification == "malicious"
    
    @property
    def is_benign(self) -> bool:
        return self.classification == "benign" or self.riot
    
    @property
    def score(self) -> float:
        if self.classification == "malicious":
            return 0.8
        elif self.classification == "unknown" and self.noise:
            return 0.5
        elif self.classification == "benign" or self.riot:
            return 0.0
        return 0.3
    
    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'found': self.found,
            'seen': self.seen,
            'classification': self.classification,
            'noise': self.noise,
            'riot': self.riot,
            'name': self.name,
            'link': self.link,
            'last_seen': self.last_seen,
            'first_seen': self.first_seen,
            'actor': self.actor,
            'tags': self.tags,
            'cve': self.cve,
            'vpn': self.vpn,
            'vpn_service': self.vpn_service,
            'bot': self.bot,
            'metadata': self.metadata,
            'is_malicious': self.is_malicious,
            'is_benign': self.is_benign,
            'score': self.score,
            'error': self.error,
        }


class GreyNoiseClient:
    """
    Client for GreyNoise API.
    
    Supports both Community API (free) and Enterprise API.
    """
    
    COMMUNITY_URL = "https://api.greynoise.io/v3/community"
    ENTERPRISE_URL = "https://api.greynoise.io/v2/noise"
    RIOT_URL = "https://api.greynoise.io/v2/riot"
    
    def __init__(self, api_key: str = None):
        """
        Initialize GreyNoise client.
        
        Args:
            api_key: API key (optional for community lookups)
        """
        self.api_key = api_key
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["key"] = api_key
    
    def check_ip(self, ip: str, use_cache: bool = True) -> GreyNoiseResult:
        """
        Check IP address in GreyNoise.
        
        Uses Community API if no API key, Enterprise API if key provided.
        
        Args:
            ip: IP address to check
            use_cache: Whether to use cache
            
        Returns:
            GreyNoiseResult
        """
        result = GreyNoiseResult(ip=ip)
        
        if use_cache:
            cached = cache.get('greynoise', ip)
            if cached:
                return from_cached(GreyNoiseResult, cached)
        
        # Try RIOT first (known good IPs)
        riot_result = self._check_riot(ip)
        if riot_result and riot_result.get('riot', False):
            result.found = True
            result.riot = True
            result.classification = "benign"
            result.name = riot_result.get('name', '')
            result.link = riot_result.get('reference', '')
            
            if use_cache:
                cache.set('greynoise', ip, result.to_dict())
            return result
        
        # Check noise database
        try:
            if self.api_key:
                # Enterprise context lookup
                response = requests.get(
                    f"https://api.greynoise.io/v2/noise/context/{ip}",
                    headers=self.headers,
                    timeout=30
                )
            else:
                # Community lookup
                response = requests.get(
                    f"{self.COMMUNITY_URL}/{ip}",
                    headers=self.headers,
                    timeout=30
                )
            
            if response.status_code == 404:
                result.found = True
                result.seen = False
                result.classification = "unknown"
            elif response.status_code == 200:
                data = response.json()
                result.found = True
                result.raw = data
                
                result.seen = data.get('seen', False)
                result.noise = data.get('noise', False)
                result.classification = data.get('classification', 'unknown')
                result.name = data.get('name', '')
                result.link = data.get('link', '')
                result.last_seen = data.get('last_seen', '')
                result.first_seen = data.get('first_seen', '')
                result.actor = data.get('actor', '')
                result.tags = data.get('tags', [])
                result.cve = data.get('cve', [])
                result.vpn = data.get('vpn', False)
                result.vpn_service = data.get('vpn_service', '')
                result.bot = data.get('bot', False)
                result.metadata = data.get('metadata', {})
            
            if use_cache and result.found:
                cache.set('greynoise', ip, result.to_dict())
                
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def _check_riot(self, ip: str) -> Optional[dict]:
        """Check RIOT database (known good IPs)."""
        try:
            response = requests.get(
                f"{self.RIOT_URL}/{ip}",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
        except requests.exceptions.RequestException:
            pass
        return None
    
    def quick_check(self, ip: str) -> dict:
        """
        Quick check - returns simple verdict.
        
        Returns:
            Dict with 'noise', 'riot', 'classification' keys
        """
        result = self.check_ip(ip)
        return {
            'ip': ip,
            'noise': result.noise,
            'riot': result.riot,
            'classification': result.classification,
            'is_malicious': result.is_malicious,
            'is_benign': result.is_benign,
        }

