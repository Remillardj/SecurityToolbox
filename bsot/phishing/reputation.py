"""
Reputation Checker Module
Integrates with VirusTotal, AbuseIPDB, URLScan.io for IOC reputation checks.
"""

import time
import base64
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


@dataclass
class ReputationResult:
    """Result from a single reputation check."""
    ioc: str
    ioc_type: str  # url, domain, ip, hash
    source: str    # virustotal, abuseipdb, urlscan
    
    # Scores
    malicious: bool = False
    suspicious: bool = False
    score: float = 0.0  # 0.0 (clean) to 1.0 (malicious)
    
    # Details
    detections: int = 0
    total_engines: int = 0
    categories: List[str] = field(default_factory=list)
    
    # Additional context
    first_seen: str = ""
    last_seen: str = ""
    country: str = ""
    asn: str = ""
    
    # Raw data
    raw_response: Dict = field(default_factory=dict)
    error: str = ""
    
    @property
    def detection_ratio(self) -> str:
        """Get detection ratio as string."""
        if self.total_engines > 0:
            return f"{self.detections}/{self.total_engines}"
        return "N/A"


@dataclass
class AggregatedReputation:
    """Aggregated reputation results for an IOC from multiple sources."""
    ioc: str
    ioc_type: str
    
    results: List[ReputationResult] = field(default_factory=list)
    
    @property
    def is_malicious(self) -> bool:
        """Check if any source flagged as malicious."""
        return any(r.malicious for r in self.results)
    
    @property
    def is_suspicious(self) -> bool:
        """Check if any source flagged as suspicious."""
        return any(r.suspicious or r.malicious for r in self.results)
    
    @property
    def max_score(self) -> float:
        """Get highest threat score across all sources."""
        if not self.results:
            return 0.0
        return max(r.score for r in self.results)
    
    @property
    def verdict(self) -> str:
        """Get overall verdict."""
        if self.is_malicious:
            return "malicious"
        elif self.is_suspicious:
            return "suspicious"
        return "clean"


class VirusTotalClient:
    """Client for VirusTotal API v3."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    
    def check_url(self, url: str) -> ReputationResult:
        """Check URL reputation."""
        import requests
        
        result = ReputationResult(
            ioc=url,
            ioc_type="url",
            source="virustotal"
        )
        
        try:
            # URL ID is base64 of URL without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            
            response = requests.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 404:
                # URL not in VT database, submit for analysis
                result.error = "URL not found in VirusTotal database"
                return result
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_analysis_result(data, url, "url")
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def check_domain(self, domain: str) -> ReputationResult:
        """Check domain reputation."""
        import requests
        
        result = ReputationResult(
            ioc=domain,
            ioc_type="domain",
            source="virustotal"
        )
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 404:
                result.error = "Domain not found in VirusTotal database"
                return result
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_analysis_result(data, domain, "domain")
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def check_ip(self, ip: str) -> ReputationResult:
        """Check IP address reputation."""
        import requests
        
        result = ReputationResult(
            ioc=ip,
            ioc_type="ip",
            source="virustotal"
        )
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 404:
                result.error = "IP not found in VirusTotal database"
                return result
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_analysis_result(data, ip, "ip")
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def check_hash(self, file_hash: str) -> ReputationResult:
        """Check file hash reputation."""
        import requests
        
        result = ReputationResult(
            ioc=file_hash,
            ioc_type="hash",
            source="virustotal"
        )
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 404:
                result.error = "Hash not found in VirusTotal database"
                return result
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_analysis_result(data, file_hash, "hash")
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def _parse_analysis_result(self, data: dict, ioc: str, ioc_type: str) -> ReputationResult:
        """Parse VirusTotal API response."""
        result = ReputationResult(
            ioc=ioc,
            ioc_type=ioc_type,
            source="virustotal"
        )
        
        try:
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            
            result.detections = stats.get('malicious', 0) + stats.get('suspicious', 0)
            result.total_engines = sum(stats.values())
            
            # Calculate score
            if result.total_engines > 0:
                result.score = result.detections / result.total_engines
            
            # Determine status
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            result.malicious = malicious_count >= 3
            result.suspicious = suspicious_count >= 2 or malicious_count >= 1
            
            # Extract categories
            categories = attrs.get('categories', {})
            if isinstance(categories, dict):
                result.categories = list(set(categories.values()))
            
            # Timestamps
            result.first_seen = attrs.get('first_submission_date', '')
            result.last_seen = attrs.get('last_analysis_date', '')
            
            # Network info
            if ioc_type == 'ip':
                result.country = attrs.get('country', '')
                result.asn = str(attrs.get('asn', ''))
            
            result.raw_response = data
            
        except Exception as e:
            result.error = f"Parse error: {str(e)}"
        
        return result


class AbuseIPDBClient:
    """Client for AbuseIPDB API v2."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
    
    def check_ip(self, ip: str) -> ReputationResult:
        """Check IP address reputation."""
        import requests
        
        result = ReputationResult(
            ioc=ip,
            ioc_type="ip",
            source="abuseipdb"
        )
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True
                },
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            result = self._parse_response(data, ip)
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result
    
    def _parse_response(self, data: dict, ip: str) -> ReputationResult:
        """Parse AbuseIPDB response."""
        result = ReputationResult(
            ioc=ip,
            ioc_type="ip",
            source="abuseipdb"
        )
        
        try:
            abuse_data = data.get('data', {})
            
            # Abuse confidence score (0-100)
            abuse_score = abuse_data.get('abuseConfidenceScore', 0)
            result.score = abuse_score / 100.0
            
            result.malicious = abuse_score >= 50
            result.suspicious = abuse_score >= 25
            
            result.detections = abuse_data.get('totalReports', 0)
            
            # Extract country and ISP
            result.country = abuse_data.get('countryCode', '')
            result.asn = abuse_data.get('isp', '')
            
            # Categories
            usage_type = abuse_data.get('usageType', '')
            if usage_type:
                result.categories.append(usage_type)
            
            domain = abuse_data.get('domain', '')
            if domain:
                result.categories.append(f"domain: {domain}")
            
            result.last_seen = abuse_data.get('lastReportedAt', '')
            result.raw_response = data
            
        except Exception as e:
            result.error = f"Parse error: {str(e)}"
        
        return result


class URLScanClient:
    """Client for URLScan.io API."""
    
    BASE_URL = "https://urlscan.io/api/v1"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["API-Key"] = api_key
    
    def check_url(self, url: str) -> ReputationResult:
        """Check URL by searching existing scans."""
        import requests
        
        result = ReputationResult(
            ioc=url,
            ioc_type="url",
            source="urlscan"
        )
        
        try:
            # Search for existing scans of this URL
            domain = urlparse(url).netloc
            
            response = requests.get(
                f"{self.BASE_URL}/search/",
                params={"q": f"domain:{domain}"},
                headers=self.headers,
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            results = data.get('results', [])
            if results:
                # Check if any scan flagged it as malicious
                for scan in results[:5]:  # Check first 5 results
                    if scan.get('verdicts', {}).get('overall', {}).get('malicious'):
                        result.malicious = True
                        result.score = 0.8
                        break
                    elif scan.get('verdicts', {}).get('overall', {}).get('score', 0) > 0:
                        result.suspicious = True
                        result.score = 0.5
                
                result.detections = len([r for r in results if r.get('verdicts', {}).get('overall', {}).get('malicious')])
                result.total_engines = len(results)
            
            result.raw_response = data
            
        except requests.exceptions.RequestException as e:
            result.error = str(e)
        
        return result


class ReputationChecker:
    """
    Aggregates reputation checks from multiple sources.
    """
    
    def __init__(
        self,
        virustotal_key: str = None,
        abuseipdb_key: str = None,
        urlscan_key: str = None
    ):
        """
        Initialize reputation checker with API keys.
        
        Args:
            virustotal_key: VirusTotal API key
            abuseipdb_key: AbuseIPDB API key  
            urlscan_key: URLScan.io API key
        """
        self.vt_client = VirusTotalClient(virustotal_key) if virustotal_key else None
        self.abuseipdb_client = AbuseIPDBClient(abuseipdb_key) if abuseipdb_key else None
        self.urlscan_client = URLScanClient(urlscan_key) if urlscan_key else None
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.5  # seconds
    
    def _rate_limit(self):
        """Apply rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def check_url(self, url: str) -> AggregatedReputation:
        """Check URL reputation across all configured sources."""
        agg = AggregatedReputation(ioc=url, ioc_type="url")
        
        if self.vt_client:
            self._rate_limit()
            result = self.vt_client.check_url(url)
            agg.results.append(result)
        
        if self.urlscan_client:
            self._rate_limit()
            result = self.urlscan_client.check_url(url)
            agg.results.append(result)
        
        return agg
    
    def check_domain(self, domain: str) -> AggregatedReputation:
        """Check domain reputation."""
        agg = AggregatedReputation(ioc=domain, ioc_type="domain")
        
        if self.vt_client:
            self._rate_limit()
            result = self.vt_client.check_domain(domain)
            agg.results.append(result)
        
        return agg
    
    def check_ip(self, ip: str) -> AggregatedReputation:
        """Check IP reputation across all configured sources."""
        agg = AggregatedReputation(ioc=ip, ioc_type="ip")
        
        if self.vt_client:
            self._rate_limit()
            result = self.vt_client.check_ip(ip)
            agg.results.append(result)
        
        if self.abuseipdb_client:
            self._rate_limit()
            result = self.abuseipdb_client.check_ip(ip)
            agg.results.append(result)
        
        return agg
    
    def check_hash(self, file_hash: str) -> AggregatedReputation:
        """Check file hash reputation."""
        agg = AggregatedReputation(ioc=file_hash, ioc_type="hash")
        
        if self.vt_client:
            self._rate_limit()
            result = self.vt_client.check_hash(file_hash)
            agg.results.append(result)
        
        return agg
    
    def check_all_iocs(self, extracted_iocs, max_per_type: int = 10) -> Dict[str, List[AggregatedReputation]]:
        """
        Check all IOCs from an ExtractedIOCs object.
        
        Args:
            extracted_iocs: ExtractedIOCs object
            max_per_type: Maximum IOCs to check per type (rate limiting)
            
        Returns:
            Dictionary of IOC type -> list of reputation results
        """
        results = {
            'urls': [],
            'domains': [],
            'ips': [],
            'hashes': []
        }
        
        # Check URLs
        for url in extracted_iocs.urls[:max_per_type]:
            result = self.check_url(url)
            results['urls'].append(result)
        
        # Check domains
        for domain in extracted_iocs.domains[:max_per_type]:
            result = self.check_domain(domain)
            results['domains'].append(result)
        
        # Check IPs
        for ip in extracted_iocs.ip_addresses[:max_per_type]:
            result = self.check_ip(ip)
            results['ips'].append(result)
        
        # Check hashes
        all_hashes = (
            extracted_iocs.file_hashes['sha256'][:max_per_type] +
            extracted_iocs.file_hashes['sha1'][:max_per_type] +
            extracted_iocs.file_hashes['md5'][:max_per_type]
        )
        for file_hash in all_hashes[:max_per_type]:
            result = self.check_hash(file_hash)
            results['hashes'].append(result)
        
        return results
    
    def get_summary(self, results: Dict[str, List[AggregatedReputation]]) -> Dict[str, Any]:
        """
        Generate summary of reputation check results.
        
        Args:
            results: Results from check_all_iocs
            
        Returns:
            Summary dictionary
        """
        summary = {
            'total_checked': 0,
            'malicious_count': 0,
            'suspicious_count': 0,
            'clean_count': 0,
            'malicious_iocs': [],
            'suspicious_iocs': []
        }
        
        for ioc_type, agg_list in results.items():
            for agg in agg_list:
                summary['total_checked'] += 1
                
                if agg.is_malicious:
                    summary['malicious_count'] += 1
                    summary['malicious_iocs'].append({
                        'ioc': agg.ioc,
                        'type': agg.ioc_type,
                        'score': agg.max_score
                    })
                elif agg.is_suspicious:
                    summary['suspicious_count'] += 1
                    summary['suspicious_iocs'].append({
                        'ioc': agg.ioc,
                        'type': agg.ioc_type,
                        'score': agg.max_score
                    })
                else:
                    summary['clean_count'] += 1
        
        return summary

