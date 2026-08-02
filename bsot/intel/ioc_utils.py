"""
IOC Utilities
Type detection, defanging, and validation for indicators of compromise.
"""

import re
from enum import Enum
from typing import Optional
import ipaddress


class IOCType(Enum):
    """Types of indicators of compromise."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    CVE = "cve"
    UNKNOWN = "unknown"


# Regex patterns for IOC detection
PATTERNS = {
    IOCType.IPV4: re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ),
    IOCType.IPV6: re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
        r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|'
        r'^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$'
    ),
    IOCType.DOMAIN: re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ),
    IOCType.URL: re.compile(
        r'^https?://[^\s<>"\']+$',
        re.IGNORECASE
    ),
    IOCType.EMAIL: re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    IOCType.MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
    IOCType.SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
    IOCType.SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
    IOCType.SHA512: re.compile(r'^[a-fA-F0-9]{128}$'),
    IOCType.CVE: re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE),
}


def detect_ioc_type(value: str) -> IOCType:
    """
    Detect the type of an IOC.
    
    Args:
        value: The IOC value to analyze
        
    Returns:
        IOCType enum value
    """
    value = value.strip()
    
    # First, try to refang the value in case it's defanged
    refanged = refang(value)
    
    # Check patterns in order of specificity
    # URLs first (they contain domains)
    if PATTERNS[IOCType.URL].match(refanged):
        return IOCType.URL
    
    # Email (contains @)
    if PATTERNS[IOCType.EMAIL].match(refanged):
        return IOCType.EMAIL
    
    # CVE
    if PATTERNS[IOCType.CVE].match(refanged):
        return IOCType.CVE
    
    # Hashes (by length)
    if PATTERNS[IOCType.SHA512].match(refanged):
        return IOCType.SHA512
    if PATTERNS[IOCType.SHA256].match(refanged):
        return IOCType.SHA256
    if PATTERNS[IOCType.SHA1].match(refanged):
        return IOCType.SHA1
    if PATTERNS[IOCType.MD5].match(refanged):
        return IOCType.MD5
    
    # IP addresses
    try:
        ip = ipaddress.ip_address(refanged)
        if isinstance(ip, ipaddress.IPv4Address):
            return IOCType.IPV4
        else:
            return IOCType.IPV6
    except ValueError:
        pass
    
    # Domain
    if PATTERNS[IOCType.DOMAIN].match(refanged):
        return IOCType.DOMAIN
    
    return IOCType.UNKNOWN


def defang(value: str, ioc_type: IOCType = None) -> str:
    """
    Defang an IOC for safe display/sharing.
    
    Args:
        value: The IOC to defang
        ioc_type: Optional type hint (auto-detected if not provided)
        
    Returns:
        Defanged IOC string
    """
    if ioc_type is None:
        ioc_type = detect_ioc_type(value)
    
    result = value
    
    if ioc_type == IOCType.URL:
        result = result.replace("http://", "hxxp://")
        result = result.replace("https://", "hxxps://")
        result = result.replace("://", "[://]")
        # Defang dots in domain part
        parts = result.split("/", 3)
        if len(parts) >= 3:
            domain_part = parts[2].replace(".", "[.]")
            parts[2] = domain_part
            result = "/".join(parts)
    
    elif ioc_type in (IOCType.DOMAIN, IOCType.EMAIL):
        result = result.replace(".", "[.]")
        if ioc_type == IOCType.EMAIL:
            result = result.replace("@", "[@]")
    
    elif ioc_type in (IOCType.IPV4, IOCType.IPV6):
        result = result.replace(".", "[.]")
        result = result.replace(":", "[:]")
    
    return result


def refang(value: str) -> str:
    """
    Refang a defanged IOC back to original form.
    
    Args:
        value: The defanged IOC
        
    Returns:
        Original IOC string
    """
    result = value

    # Separators are normalised before the scheme rules run: `hxxp[://]` does
    # not match a `hxxp://` rule, so replacing schemes first left the scheme
    # itself defanged.
    result = result.replace("[://]", "://")
    result = result.replace("[:]//", "://")

    # URL schemes
    result = result.replace("hxxp://", "http://")
    result = result.replace("hxxps://", "https://")
    result = result.replace("hXXp://", "http://")
    result = result.replace("hXXps://", "https://")

    # Brackets around separators
    result = result.replace("[.]", ".")
    result = result.replace("[:]", ":")
    result = result.replace("[@]", "@")
    result = result.replace("[/]", "/")
    
    # Common variations
    result = result.replace("(.)", ".")
    result = result.replace("{.}", ".")
    result = result.replace(" . ", ".")
    result = result.replace(" dot ", ".")
    result = result.replace("[dot]", ".")
    result = result.replace("(dot)", ".")
    
    return result


def validate_ioc(value: str, expected_type: IOCType = None) -> bool:
    """
    Validate an IOC value.
    
    Args:
        value: The IOC to validate
        expected_type: Optional expected type
        
    Returns:
        True if valid
    """
    detected = detect_ioc_type(refang(value))
    
    if expected_type:
        return detected == expected_type
    
    return detected != IOCType.UNKNOWN


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from a URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(refang(url))
        return parsed.netloc or None
    except Exception:
        return None


def extract_iocs_from_text(text: str) -> dict:
    """
    Extract all IOCs from text.
    
    Args:
        text: Text to scan
        
    Returns:
        Dict of IOC type -> list of values
    """
    results = {
        'ipv4': [],
        'ipv6': [],
        'domains': [],
        'urls': [],
        'emails': [],
        'md5': [],
        'sha1': [],
        'sha256': [],
        'sha512': [],
        'cves': [],
    }
    
    # URL pattern (extract first)
    url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    for match in url_pattern.finditer(text):
        url = match.group()
        if url not in results['urls']:
            results['urls'].append(url)
    
    # Remove URLs from text for other extractions
    text_no_urls = url_pattern.sub(' ', text)
    
    # IPv4
    ipv4_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    for match in ipv4_pattern.finditer(text_no_urls):
        ip = match.group()
        if ip not in results['ipv4']:
            try:
                ipaddress.IPv4Address(ip)
                results['ipv4'].append(ip)
            except ValueError:
                pass
    
    # Email
    email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    for match in email_pattern.finditer(text_no_urls):
        email = match.group().lower()
        if email not in results['emails']:
            results['emails'].append(email)
    
    # Hashes
    hash_patterns = [
        ('sha512', re.compile(r'\b[a-fA-F0-9]{128}\b')),
        ('sha256', re.compile(r'\b[a-fA-F0-9]{64}\b')),
        ('sha1', re.compile(r'\b[a-fA-F0-9]{40}\b')),
        ('md5', re.compile(r'\b[a-fA-F0-9]{32}\b')),
    ]
    
    remaining_text = text_no_urls
    for hash_type, pattern in hash_patterns:
        for match in pattern.finditer(remaining_text):
            h = match.group().lower()
            if h not in results[hash_type]:
                results[hash_type].append(h)
        # Remove found hashes to avoid substring matches
        remaining_text = pattern.sub(' ', remaining_text)
    
    # CVE
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
    for match in cve_pattern.finditer(text):
        cve = match.group().upper()
        if cve not in results['cves']:
            results['cves'].append(cve)
    
    # Domain (after removing emails and URLs)
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    for match in domain_pattern.finditer(text_no_urls):
        domain = match.group().lower()
        # Exclude if it's an email domain
        if domain not in results['domains'] and not any(domain in e for e in results['emails']):
            results['domains'].append(domain)
    
    return results

