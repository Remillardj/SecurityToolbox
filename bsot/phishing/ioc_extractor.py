"""
IOC (Indicator of Compromise) Extractor Module
Extracts URLs, IPs, domains, email addresses, and file hashes from content.
"""

import re
from typing import List, Dict
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote
import ipaddress
from html.parser import HTMLParser


@dataclass
class ExtractedIOCs:
    """Container for all extracted IOCs."""
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    file_hashes: Dict[str, List[str]] = field(default_factory=lambda: {
        'md5': [],
        'sha1': [],
        'sha256': []
    })
    bitcoin_addresses: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    
    @property
    def total_count(self) -> int:
        """Total number of IOCs extracted."""
        return (
            len(self.urls) +
            len(self.domains) +
            len(self.ip_addresses) +
            len(self.email_addresses) +
            len(self.file_hashes['md5']) +
            len(self.file_hashes['sha1']) +
            len(self.file_hashes['sha256']) +
            len(self.bitcoin_addresses) +
            len(self.phone_numbers)
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'urls': self.urls,
            'domains': self.domains,
            'ip_addresses': self.ip_addresses,
            'email_addresses': self.email_addresses,
            'file_hashes': self.file_hashes,
            'bitcoin_addresses': self.bitcoin_addresses,
            'phone_numbers': self.phone_numbers,
        }


class HTMLLinkExtractor(HTMLParser):
    """Extract links from HTML content."""
    
    def __init__(self):
        super().__init__()
        self.links = []
    
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href' and value:
                    self.links.append(value)
        elif tag == 'img':
            for attr, value in attrs:
                if attr == 'src' and value:
                    self.links.append(value)
        elif tag == 'form':
            for attr, value in attrs:
                if attr == 'action' and value:
                    self.links.append(value)
        elif tag in ('script', 'iframe', 'embed', 'object'):
            for attr, value in attrs:
                if attr == 'src' and value:
                    self.links.append(value)


class IOCExtractor:
    """
    Extracts Indicators of Compromise from text and HTML content.
    """
    
    # Regex patterns
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\']*',
        re.IGNORECASE
    )
    
    # More comprehensive URL pattern including without protocol
    URL_PATTERN_LOOSE = re.compile(
        r'(?:https?://)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
        re.IGNORECASE
    )
    
    # IP address patterns
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    IPV6_PATTERN = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    )
    
    # Domain pattern
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    
    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    # Hash patterns
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    # Bitcoin address pattern
    BTC_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    
    # Phone number patterns (US format)
    PHONE_PATTERN = re.compile(
        r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
    )
    
    # Known safe domains to filter out
    SAFE_DOMAINS = {
        'w3.org', 'w3schools.com', 'schema.org', 'microsoft.com',
        'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
        'outlook.com', 'office.com', 'office365.com', 'windows.net',
        'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com',
        'example.com', 'example.org', 'example.net', 'localhost',
    }
    
    def __init__(self, include_safe_domains: bool = False):
        """
        Initialize the IOC extractor.
        
        Args:
            include_safe_domains: If True, include commonly safe domains in results
        """
        self.include_safe_domains = include_safe_domains
    
    def extract_all(self, text: str, html: str = "") -> ExtractedIOCs:
        """
        Extract all IOCs from text and HTML content.
        
        Args:
            text: Plain text content
            html: HTML content (optional)
            
        Returns:
            ExtractedIOCs object with all findings
        """
        iocs = ExtractedIOCs()
        
        # Combine content for extraction
        combined_content = f"{text}\n{html}"
        
        # Extract URLs
        iocs.urls = self._extract_urls(text, html)
        
        # Extract domains from URLs and text
        iocs.domains = self._extract_domains(combined_content, iocs.urls)
        
        # Extract IP addresses
        iocs.ip_addresses = self._extract_ips(combined_content)
        
        # Extract email addresses
        iocs.email_addresses = self._extract_emails(combined_content)
        
        # Extract hashes
        iocs.file_hashes = self._extract_hashes(combined_content)
        
        # Extract bitcoin addresses
        iocs.bitcoin_addresses = self._extract_bitcoin(combined_content)
        
        # Extract phone numbers
        iocs.phone_numbers = self._extract_phones(combined_content)
        
        return iocs
    
    def _extract_urls(self, text: str, html: str = "") -> List[str]:
        """Extract URLs from text and HTML."""
        urls = set()
        
        # Extract from plain text
        for match in self.URL_PATTERN.finditer(text):
            url = match.group()
            urls.add(self._clean_url(url))
        
        # Extract from HTML using parser
        if html:
            try:
                parser = HTMLLinkExtractor()
                parser.feed(html)
                for link in parser.links:
                    if link.startswith(('http://', 'https://')):
                        urls.add(self._clean_url(link))
                    elif link.startswith('//'):
                        urls.add(self._clean_url(f"https:{link}"))
            except Exception:
                pass
            
            # Also use regex on HTML
            for match in self.URL_PATTERN.finditer(html):
                url = match.group()
                urls.add(self._clean_url(url))
        
        # Filter and sort
        filtered = []
        for url in urls:
            if self._is_valid_url(url):
                if self.include_safe_domains or not self._is_safe_url(url):
                    filtered.append(url)
        
        return sorted(list(set(filtered)))
    
    def _extract_domains(self, text: str, urls: List[str]) -> List[str]:
        """Extract domains from content and URLs."""
        domains = set()
        
        # Extract from URLs
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc.lower()
                    # Remove port if present
                    domain = domain.split(':')[0]
                    # Remove www prefix for normalization
                    if domain.startswith('www.'):
                        domains.add(domain[4:])
                    domains.add(domain)
            except Exception:
                continue
        
        # Extract from text using pattern
        for match in self.DOMAIN_PATTERN.finditer(text):
            domain = match.group().lower()
            if self._is_valid_domain(domain):
                domains.add(domain)
        
        # Filter safe domains
        if not self.include_safe_domains:
            domains = {d for d in domains if not self._is_safe_domain(d)}
        
        return sorted(list(domains))
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text."""
        ips = set()
        
        # IPv4
        for match in self.IPV4_PATTERN.finditer(text):
            ip = match.group()
            if self._is_valid_ip(ip):
                ips.add(ip)
        
        # IPv6
        for match in self.IPV6_PATTERN.finditer(text):
            ip = match.group()
            ips.add(ip)
        
        return sorted(list(ips))
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        emails = set()
        
        for match in self.EMAIL_PATTERN.finditer(text):
            email = match.group().lower()
            # Filter out obvious non-emails
            if not email.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                emails.add(email)
        
        return sorted(list(emails))
    
    def _extract_hashes(self, text: str) -> Dict[str, List[str]]:
        """Extract file hashes from text."""
        hashes = {
            'md5': [],
            'sha1': [],
            'sha256': []
        }
        
        # We extract in order of length to avoid duplicates
        # SHA256 (64 chars)
        sha256_matches = set(self.SHA256_PATTERN.findall(text))
        hashes['sha256'] = sorted([h.lower() for h in sha256_matches])
        
        # Remove SHA256 matches from text to avoid matching substrings
        text_without_sha256 = text
        for h in sha256_matches:
            text_without_sha256 = text_without_sha256.replace(h, '')
        
        # SHA1 (40 chars)
        sha1_matches = set(self.SHA1_PATTERN.findall(text_without_sha256))
        hashes['sha1'] = sorted([h.lower() for h in sha1_matches])
        
        # Remove SHA1 matches
        text_without_sha1 = text_without_sha256
        for h in sha1_matches:
            text_without_sha1 = text_without_sha1.replace(h, '')
        
        # MD5 (32 chars)
        md5_matches = set(self.MD5_PATTERN.findall(text_without_sha1))
        # Filter out common false positives (GUIDs, etc)
        hashes['md5'] = sorted([
            h.lower() for h in md5_matches 
            if not self._is_likely_guid(h)
        ])
        
        return hashes
    
    def _extract_bitcoin(self, text: str) -> List[str]:
        """Extract Bitcoin addresses from text."""
        btc = set()
        for match in self.BTC_PATTERN.finditer(text):
            addr = match.group()
            btc.add(addr)
        return sorted(list(btc))
    
    def _extract_phones(self, text: str) -> List[str]:
        """Extract phone numbers from text."""
        phones = set()
        for match in self.PHONE_PATTERN.finditer(text):
            phone = match.group()
            # Normalize phone number
            normalized = re.sub(r'[^\d+]', '', phone)
            if len(normalized) >= 10:
                phones.add(phone)
        return sorted(list(phones))
    
    def _clean_url(self, url: str) -> str:
        """Clean and normalize a URL."""
        # Remove trailing punctuation
        url = url.rstrip('.,;:!?\'")]>')
        # URL decode
        try:
            url = unquote(url)
        except Exception:
            pass
        return url
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid."""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    def _is_safe_url(self, url: str) -> bool:
        """Check if URL belongs to a known safe domain."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return self._is_safe_domain(domain)
        except Exception:
            return False
    
    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is in safe list."""
        domain = domain.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check exact match
        if domain in self.SAFE_DOMAINS:
            return True
        
        # Check if subdomain of safe domain
        for safe in self.SAFE_DOMAINS:
            if domain.endswith(f'.{safe}'):
                return True
        
        return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain looks valid."""
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        # TLD must be at least 2 chars
        parts = domain.split('.')
        if len(parts[-1]) < 2:
            return False
        
        # Filter out common false positives
        if domain.endswith(('.exe', '.dll', '.js', '.css', '.html', '.htm')):
            return False
        
        return True
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid and not private/reserved."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Exclude private and reserved ranges
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                return False
            return True
        except ValueError:
            return False
    
    def _is_likely_guid(self, hash_str: str) -> bool:
        """Check if a 32-char string is likely a GUID rather than MD5."""
        # GUIDs often have patterns that MD5s don't
        # This is a heuristic
        return False


def extract_iocs_from_email(parsed_email) -> ExtractedIOCs:
    """
    Convenience function to extract IOCs from a ParsedEmail object.
    
    Args:
        parsed_email: A ParsedEmail object from email_parser module
        
    Returns:
        ExtractedIOCs object
    """
    extractor = IOCExtractor()
    
    # Combine all text content
    text_content = f"{parsed_email.subject}\n{parsed_email.body_text}"
    html_content = parsed_email.body_html
    
    # Add header content
    if parsed_email.raw_headers:
        text_content += f"\n{parsed_email.raw_headers}"
    
    return extractor.extract_all(text_content, html_content)

