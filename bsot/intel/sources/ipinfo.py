"""
IPInfo.io API Client
IP Geolocation and ASN information.
"""

import requests
from typing import Optional
from dataclasses import dataclass, field

from ...cache import cache, from_cached


@dataclass
class IPInfoResult:
    """IPInfo lookup result."""
    ip: str
    found: bool = False
    hostname: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    country_name: str = ""
    loc: str = ""  # latitude,longitude
    org: str = ""  # ASN and org name
    asn: str = ""
    asn_name: str = ""
    postal: str = ""
    timezone: str = ""
    is_bogon: bool = False
    is_anycast: bool = False
    is_datacenter: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_relay: bool = False
    company_name: str = ""
    company_type: str = ""
    carrier_name: str = ""
    carrier_mcc: str = ""
    carrier_mnc: str = ""
    error: str = ""
    raw: dict = field(default_factory=dict)
    
    @property
    def latitude(self) -> Optional[float]:
        if self.loc:
            try:
                return float(self.loc.split(',')[0])
            except (ValueError, IndexError):
                pass
        return None
    
    @property
    def longitude(self) -> Optional[float]:
        if self.loc:
            try:
                return float(self.loc.split(',')[1])
            except (ValueError, IndexError):
                pass
        return None
    
    @property
    def is_suspicious(self) -> bool:
        """Check if IP has suspicious characteristics."""
        return self.is_vpn or self.is_proxy or self.is_tor
    
    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'found': self.found,
            'hostname': self.hostname,
            'city': self.city,
            'region': self.region,
            'country': self.country,
            'country_name': self.country_name,
            'loc': self.loc,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'org': self.org,
            'asn': self.asn,
            'asn_name': self.asn_name,
            'postal': self.postal,
            'timezone': self.timezone,
            'is_bogon': self.is_bogon,
            'is_anycast': self.is_anycast,
            'is_datacenter': self.is_datacenter,
            'is_vpn': self.is_vpn,
            'is_proxy': self.is_proxy,
            'is_tor': self.is_tor,
            'is_relay': self.is_relay,
            'is_suspicious': self.is_suspicious,
            'company_name': self.company_name,
            'company_type': self.company_type,
            'error': self.error,
        }


# Country code to name mapping (common ones)
COUNTRY_NAMES = {
    'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada',
    'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'JP': 'Japan',
    'CN': 'China', 'RU': 'Russia', 'BR': 'Brazil', 'IN': 'India',
    'KR': 'South Korea', 'NL': 'Netherlands', 'IT': 'Italy', 'ES': 'Spain',
    'SE': 'Sweden', 'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland',
    'PL': 'Poland', 'CH': 'Switzerland', 'AT': 'Austria', 'BE': 'Belgium',
    'IE': 'Ireland', 'NZ': 'New Zealand', 'SG': 'Singapore', 'HK': 'Hong Kong',
    'TW': 'Taiwan', 'MX': 'Mexico', 'AR': 'Argentina', 'ZA': 'South Africa',
    'UA': 'Ukraine', 'CZ': 'Czech Republic', 'RO': 'Romania', 'HU': 'Hungary',
    'IL': 'Israel', 'AE': 'United Arab Emirates', 'TH': 'Thailand',
    'VN': 'Vietnam', 'ID': 'Indonesia', 'MY': 'Malaysia', 'PH': 'Philippines',
}


class IPInfoClient:
    """
    Client for IPInfo.io API.
    
    Works without API key (limited requests) or with token for higher limits.
    """
    
    BASE_URL = "https://ipinfo.io"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
    
    def lookup(self, ip: str, use_cache: bool = True) -> IPInfoResult:
        """
        Look up IP address information.
        
        Args:
            ip: IP address to look up
            use_cache: Whether to use cache
            
        Returns:
            IPInfoResult
        """
        result = IPInfoResult(ip=ip)
        
        if use_cache:
            cached = cache.get('ipinfo', ip)
            if cached:
                return from_cached(IPInfoResult, cached)
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/{ip}/json",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 429:
                result.error = "Rate limit exceeded"
                return result
            
            response.raise_for_status()
            data = response.json()
            
            result.found = True
            result.raw = data
            
            result.hostname = data.get('hostname', '')
            result.city = data.get('city', '')
            result.region = data.get('region', '')
            result.country = data.get('country', '')
            result.country_name = COUNTRY_NAMES.get(result.country, result.country)
            result.loc = data.get('loc', '')
            result.org = data.get('org', '')
            result.postal = data.get('postal', '')
            result.timezone = data.get('timezone', '')
            result.is_bogon = data.get('bogon', False)
            
            # Parse ASN from org field (format: "AS1234 Organization Name")
            if result.org and result.org.startswith('AS'):
                parts = result.org.split(' ', 1)
                result.asn = parts[0]
                result.asn_name = parts[1] if len(parts) > 1 else ''
            
            # Privacy/security info (available with paid API)
            privacy = data.get('privacy', {})
            if privacy:
                result.is_vpn = privacy.get('vpn', False)
                result.is_proxy = privacy.get('proxy', False)
                result.is_tor = privacy.get('tor', False)
                result.is_relay = privacy.get('relay', False)
            
            # Company info
            company = data.get('company', {})
            if company:
                result.company_name = company.get('name', '')
                result.company_type = company.get('type', '')
            
            # ASN details (if available)
            asn_data = data.get('asn', {})
            if asn_data:
                result.asn = asn_data.get('asn', result.asn)
                result.asn_name = asn_data.get('name', result.asn_name)
            
            # Carrier info (for mobile IPs)
            carrier = data.get('carrier', {})
            if carrier:
                result.carrier_name = carrier.get('name', '')
                result.carrier_mcc = carrier.get('mcc', '')
                result.carrier_mnc = carrier.get('mnc', '')
            
            # Check for datacenter/hosting
            if result.company_type in ('hosting', 'isp'):
                result.is_datacenter = True
            
            if use_cache:
                cache.set('ipinfo', ip, result.to_dict(), ttl_hours=168)  # 7 days
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def lookup_asn(self, asn: str) -> dict:
        """
        Look up ASN information.
        
        Args:
            asn: ASN number (with or without 'AS' prefix)
            
        Returns:
            Dict with ASN info
        """
        if not asn.upper().startswith('AS'):
            asn = f"AS{asn}"
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/{asn}/json",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return {}

