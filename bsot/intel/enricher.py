"""
IOC Enricher
Multi-source enrichment for indicators of compromise.
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from .ioc_utils import detect_ioc_type
from ..config import config


@dataclass
class EnrichmentResult:
    """Aggregated enrichment result from multiple sources."""
    ioc: str
    ioc_type: str
    
    # Overall verdict
    verdict: str = "unknown"  # malicious, suspicious, clean, unknown
    confidence: float = 0.0
    
    # Aggregated scores
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    
    # Source results
    sources: Dict[str, Any] = field(default_factory=dict)
    
    # Aggregated data
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    
    # Context
    first_seen: str = ""
    last_seen: str = ""
    country: str = ""
    asn: str = ""
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'ioc': self.ioc,
            'ioc_type': self.ioc_type,
            'verdict': self.verdict,
            'confidence': self.confidence,
            'malicious_count': self.malicious_count,
            'suspicious_count': self.suspicious_count,
            'clean_count': self.clean_count,
            'sources': self.sources,
            'tags': list(set(self.tags)),
            'categories': list(set(self.categories)),
            'malware_families': list(set(self.malware_families)),
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'country': self.country,
            'asn': self.asn,
            'errors': self.errors,
        }


class IOCEnricher:
    """
    Enriches IOCs using multiple threat intelligence sources.
    
    Supported sources:
    - VirusTotal
    - AbuseIPDB
    - GreyNoise
    - AlienVault OTX
    - IPInfo (for geolocation)
    """
    
    AVAILABLE_SOURCES = {
        'vt': ('virustotal', 'VirusTotal'),
        'virustotal': ('virustotal', 'VirusTotal'),
        'abuseipdb': ('abuseipdb', 'AbuseIPDB'),
        'greynoise': ('greynoise', 'GreyNoise'),
        'otx': ('otx', 'AlienVault OTX'),
        'ipinfo': ('ipinfo', 'IPInfo'),
    }
    
    def __init__(
        self,
        virustotal_key: str = None,
        abuseipdb_key: str = None,
        greynoise_key: str = None,
        otx_key: str = None,
        ipinfo_key: str = None,
        use_cache: bool = True
    ):
        """
        Initialize enricher with API keys.
        
        API keys can be provided directly or loaded from config.
        """
        self.use_cache = use_cache
        
        # Get keys from config if not provided
        self.vt_key = virustotal_key or config.virustotal_api_key
        self.abuseipdb_key = abuseipdb_key or config.abuseipdb_api_key
        self.greynoise_key = greynoise_key or config.greynoise_api_key
        self.otx_key = otx_key or config.otx_api_key
        self.ipinfo_key = ipinfo_key or config.ipinfo_api_key
        
        # Initialize clients
        self._init_clients()
    
    def _init_clients(self):
        """Initialize API clients."""
        self.clients = {}
        
        if self.vt_key:
            from .sources.virustotal import VirusTotalClient
            self.clients['virustotal'] = VirusTotalClient(self.vt_key)
        
        if self.abuseipdb_key:
            from .sources.abuseipdb import AbuseIPDBClient
            self.clients['abuseipdb'] = AbuseIPDBClient(self.abuseipdb_key)
        
        if self.greynoise_key:
            from .sources.greynoise import GreyNoiseClient
            self.clients['greynoise'] = GreyNoiseClient(self.greynoise_key)
        
        if self.otx_key:
            from .sources.otx import OTXClient
            self.clients['otx'] = OTXClient(self.otx_key)
        
        if self.ipinfo_key:
            from .sources.ipinfo import IPInfoClient
            self.clients['ipinfo'] = IPInfoClient(self.ipinfo_key)
    
    def get_available_sources(self, ioc_type: str = None) -> List[str]:
        """Get list of configured sources."""
        sources = list(self.clients.keys())
        
        # Filter by IOC type capability
        if ioc_type:
            if ioc_type in ('ipv4', 'ipv6', 'ip'):
                return [s for s in sources]  # All support IP
            elif ioc_type == 'domain':
                return [s for s in sources if s in ('virustotal', 'otx')]
            elif ioc_type == 'url':
                return [s for s in sources if s in ('virustotal', 'otx')]
            elif ioc_type in ('md5', 'sha1', 'sha256', 'sha512', 'hash'):
                return [s for s in sources if s in ('virustotal', 'otx')]
        
        return sources
    
    def enrich(
        self,
        ioc: str,
        sources: List[str] = None,
        ioc_type: str = None
    ) -> EnrichmentResult:
        """
        Enrich a single IOC using configured sources.
        
        Args:
            ioc: The IOC to enrich
            sources: List of sources to use (default: all available)
            ioc_type: IOC type hint (auto-detected if not provided)
            
        Returns:
            EnrichmentResult with aggregated data
        """
        # Detect IOC type
        if not ioc_type:
            detected = detect_ioc_type(ioc)
            ioc_type = detected.value
        
        result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)
        
        # Determine which sources to use
        available = self.get_available_sources(ioc_type)
        if sources:
            # Normalize source names
            sources = [self.AVAILABLE_SOURCES.get(s.lower(), (s, s))[0] for s in sources]
            sources = [s for s in sources if s in available]
        else:
            sources = available
        
        if not sources:
            result.errors.append("No sources available for this IOC type")
            return result
        
        # Query each source
        source_results = {}
        
        for source in sources:
            try:
                if source == 'virustotal':
                    source_results['virustotal'] = self._query_virustotal(ioc, ioc_type)
                elif source == 'abuseipdb' and ioc_type in ('ipv4', 'ipv6', 'ip'):
                    source_results['abuseipdb'] = self._query_abuseipdb(ioc)
                elif source == 'greynoise' and ioc_type in ('ipv4', 'ipv6', 'ip'):
                    source_results['greynoise'] = self._query_greynoise(ioc)
                elif source == 'otx':
                    source_results['otx'] = self._query_otx(ioc, ioc_type)
                elif source == 'ipinfo' and ioc_type in ('ipv4', 'ipv6', 'ip'):
                    source_results['ipinfo'] = self._query_ipinfo(ioc)
            except Exception as e:
                result.errors.append(f"{source}: {str(e)}")
        
        # Aggregate results
        result.sources = source_results
        self._aggregate_results(result, source_results)
        
        return result
    
    def _query_virustotal(self, ioc: str, ioc_type: str) -> dict:
        """Query VirusTotal."""
        client = self.clients['virustotal']
        vt_result = client.lookup(ioc, ioc_type, use_cache=self.use_cache)
        return {
            'malicious': vt_result.malicious,
            'suspicious': vt_result.suspicious,
            'total': vt_result.total_engines,
            'detection_ratio': vt_result.detection_ratio,
            'is_malicious': vt_result.is_malicious,
            'is_suspicious': vt_result.is_suspicious,
            'score': vt_result.score,
            'tags': vt_result.tags,
            'categories': vt_result.categories,
            'link': vt_result.permalink,
        }
    
    def _query_abuseipdb(self, ip: str) -> dict:
        """Query AbuseIPDB."""
        client = self.clients['abuseipdb']
        result = client.check_ip(ip, use_cache=self.use_cache)
        return {
            'abuse_score': result.abuse_confidence_score,
            'total_reports': result.total_reports,
            'is_malicious': result.is_malicious,
            'is_suspicious': result.is_suspicious,
            'score': result.score,
            'country': result.country_code,
            'isp': result.isp,
            'categories': result.categories,
            'is_tor': result.is_tor,
        }
    
    def _query_greynoise(self, ip: str) -> dict:
        """Query GreyNoise."""
        client = self.clients['greynoise']
        result = client.check_ip(ip, use_cache=self.use_cache)
        return {
            'seen': result.seen,
            'classification': result.classification,
            'noise': result.noise,
            'riot': result.riot,
            'is_malicious': result.is_malicious,
            'is_benign': result.is_benign,
            'score': result.score,
            'name': result.name,
            'actor': result.actor,
            'tags': result.tags,
            'cve': result.cve,
            'vpn': result.vpn,
        }
    
    def _query_otx(self, ioc: str, ioc_type: str) -> dict:
        """Query AlienVault OTX."""
        client = self.clients['otx']
        result = client.lookup(ioc, ioc_type, use_cache=self.use_cache)
        return {
            'pulse_count': result.pulse_count,
            'is_malicious': result.is_malicious,
            'is_suspicious': result.is_suspicious,
            'score': result.score,
            'tags': result.tags,
            'malware_families': result.malware_families,
            'adversaries': result.adversaries,
            'passive_dns': result.passive_dns[:5],
        }
    
    def _query_ipinfo(self, ip: str) -> dict:
        """Query IPInfo."""
        client = self.clients['ipinfo']
        result = client.lookup(ip, use_cache=self.use_cache)
        return {
            'country': result.country,
            'country_name': result.country_name,
            'city': result.city,
            'region': result.region,
            'org': result.org,
            'asn': result.asn,
            'asn_name': result.asn_name,
            'is_vpn': result.is_vpn,
            'is_proxy': result.is_proxy,
            'is_tor': result.is_tor,
            'is_datacenter': result.is_datacenter,
            'is_suspicious': result.is_suspicious,
            'loc': result.loc,
        }
    
    def _aggregate_results(self, result: EnrichmentResult, source_results: dict):
        """Aggregate results from multiple sources."""
        total_sources = len(source_results)
        
        for source, data in source_results.items():
            if not data:
                continue
            
            # Count verdicts
            if data.get('is_malicious'):
                result.malicious_count += 1
            elif data.get('is_suspicious'):
                result.suspicious_count += 1
            else:
                result.clean_count += 1
            
            # Aggregate tags
            if data.get('tags'):
                result.tags.extend(data['tags'])
            
            # Aggregate categories
            if data.get('categories'):
                result.categories.extend(data['categories'])
            
            # Malware families
            if data.get('malware_families'):
                result.malware_families.extend(data['malware_families'])
            
            # Context
            if data.get('country') and not result.country:
                result.country = data.get('country_name') or data.get('country', '')
            
            if data.get('asn') and not result.asn:
                result.asn = data.get('asn', '')
        
        # Calculate overall verdict
        if result.malicious_count >= 2 or (result.malicious_count >= 1 and total_sources <= 2):
            result.verdict = "malicious"
            result.confidence = min(0.9, 0.5 + (result.malicious_count * 0.2))
        elif result.malicious_count >= 1 or result.suspicious_count >= 2:
            result.verdict = "suspicious"
            result.confidence = min(0.7, 0.4 + (result.suspicious_count * 0.1))
        elif result.clean_count >= 2:
            result.verdict = "clean"
            result.confidence = min(0.8, 0.3 + (result.clean_count * 0.15))
        else:
            result.verdict = "unknown"
            result.confidence = 0.0
        
        # Deduplicate
        result.tags = list(set(result.tags))
        result.categories = list(set(result.categories))
        result.malware_families = list(set(result.malware_families))
    
    def enrich_bulk(
        self,
        iocs: List[str],
        sources: List[str] = None,
        max_concurrent: int = 5,
        show_progress: bool = False
    ) -> List[EnrichmentResult]:
        """
        Enrich multiple IOCs.
        
        Args:
            iocs: List of IOCs to enrich
            sources: Sources to use
            max_concurrent: Maximum concurrent lookups
            show_progress: Show progress bar
            
        Returns:
            List of EnrichmentResult
        """
        results = []
        
        def enrich_single(ioc):
            return self.enrich(ioc, sources=sources)
        
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            if show_progress:
                try:
                    from rich.progress import Progress
                    with Progress() as progress:
                        task = progress.add_task("Enriching IOCs...", total=len(iocs))
                        futures = {executor.submit(enrich_single, ioc): ioc for ioc in iocs}
                        for future in as_completed(futures):
                            results.append(future.result())
                            progress.advance(task)
                except ImportError:
                    futures = {executor.submit(enrich_single, ioc): ioc for ioc in iocs}
                    for future in as_completed(futures):
                        results.append(future.result())
            else:
                futures = {executor.submit(enrich_single, ioc): ioc for ioc in iocs}
                for future in as_completed(futures):
                    results.append(future.result())
        
        return results

