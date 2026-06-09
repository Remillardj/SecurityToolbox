"""
AbuseIPDB API Client
"""

import requests
from typing import Optional
from dataclasses import dataclass, field

from ...cache import cache


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB lookup result."""
    ip: str
    found: bool = False
    abuse_confidence_score: int = 0
    total_reports: int = 0
    is_whitelisted: bool = False
    is_public: bool = True
    is_tor: bool = False
    country_code: str = ""
    country_name: str = ""
    isp: str = ""
    domain: str = ""
    usage_type: str = ""
    last_reported_at: str = ""
    categories: list = field(default_factory=list)
    error: str = ""
    raw: dict = field(default_factory=dict)
    
    @property
    def is_malicious(self) -> bool:
        return self.abuse_confidence_score >= 50
    
    @property
    def is_suspicious(self) -> bool:
        return self.abuse_confidence_score >= 25
    
    @property
    def score(self) -> float:
        return self.abuse_confidence_score / 100.0
    
    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'found': self.found,
            'abuse_confidence_score': self.abuse_confidence_score,
            'total_reports': self.total_reports,
            'is_whitelisted': self.is_whitelisted,
            'is_public': self.is_public,
            'is_tor': self.is_tor,
            'country_code': self.country_code,
            'country_name': self.country_name,
            'isp': self.isp,
            'domain': self.domain,
            'usage_type': self.usage_type,
            'last_reported_at': self.last_reported_at,
            'categories': self.categories,
            'is_malicious': self.is_malicious,
            'is_suspicious': self.is_suspicious,
            'score': self.score,
            'error': self.error,
        }


# AbuseIPDB category mapping
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBClient:
    """Client for AbuseIPDB API v2."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
    
    def check_ip(self, ip: str, max_age_days: int = 90, use_cache: bool = True) -> AbuseIPDBResult:
        """
        Check IP address reputation.
        
        Args:
            ip: IP address to check
            max_age_days: How far back to look for reports (max 365)
            use_cache: Whether to use cache
            
        Returns:
            AbuseIPDBResult
        """
        result = AbuseIPDBResult(ip=ip)
        
        if use_cache:
            cached = cache.get('abuseipdb', ip)
            if cached:
                return AbuseIPDBResult(**cached)
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": min(max_age_days, 365),
                    "verbose": True
                },
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            abuse_data = data.get('data', {})
            
            result.found = True
            result.abuse_confidence_score = abuse_data.get('abuseConfidenceScore', 0)
            result.total_reports = abuse_data.get('totalReports', 0)
            result.is_whitelisted = abuse_data.get('isWhitelisted', False)
            result.is_public = abuse_data.get('isPublic', True)
            result.is_tor = abuse_data.get('isTor', False)
            result.country_code = abuse_data.get('countryCode', '')
            result.country_name = abuse_data.get('countryName', '')
            result.isp = abuse_data.get('isp', '')
            result.domain = abuse_data.get('domain', '')
            result.usage_type = abuse_data.get('usageType', '')
            result.last_reported_at = abuse_data.get('lastReportedAt', '')
            
            # Parse categories from reports
            reports = abuse_data.get('reports', [])
            category_ids = set()
            for report in reports:
                category_ids.update(report.get('categories', []))
            
            result.categories = [
                ABUSE_CATEGORIES.get(cat_id, f"Unknown ({cat_id})")
                for cat_id in category_ids
            ]
            
            result.raw = data
            
            if use_cache:
                cache.set('abuseipdb', ip, result.to_dict())
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def check_block(self, network: str, max_age_days: int = 90) -> list:
        """
        Check a CIDR block for reported IPs.
        
        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            max_age_days: How far back to look
            
        Returns:
            List of reported IPs in the block
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/check-block",
                headers=self.headers,
                params={
                    "network": network,
                    "maxAgeInDays": min(max_age_days, 365)
                },
                timeout=60
            )
            
            response.raise_for_status()
            data = response.json()
            
            return data.get('data', {}).get('reportedAddress', [])
            
        except requests.exceptions.RequestException:
            return []

