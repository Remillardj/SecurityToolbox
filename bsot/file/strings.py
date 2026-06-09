"""
String Extractor
Extract printable strings from binary files.
"""

import re
from pathlib import Path
from typing import List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class ExtractedString:
    """A single extracted string."""
    value: str
    offset: int
    encoding: str  # 'ascii' or 'unicode'
    length: int
    category: str = ""  # url, ip, email, path, registry, etc.


@dataclass
class StringExtractionResult:
    """Result of string extraction."""
    file_path: str
    file_size: int
    total_strings: int
    strings: List[ExtractedString] = field(default_factory=list)
    
    # Categorized strings
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    interesting: List[str] = field(default_factory=list)
    
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'file_path': self.file_path,
            'file_size': self.file_size,
            'total_strings': self.total_strings,
            'urls': self.urls,
            'ips': self.ips,
            'emails': self.emails,
            'paths': self.paths,
            'registry_keys': self.registry_keys,
            'interesting': self.interesting,
            'error': self.error,
        }


class StringExtractor:
    """
    Extract printable strings from binary files.
    """
    
    # Patterns for categorization
    PATTERNS = {
        'url': re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE),
        'ip': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'windows_path': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
        'unix_path': re.compile(r'(?:/[a-zA-Z0-9._-]+)+/?'),
        'registry': re.compile(r'HKEY_[A-Z_]+(?:\\[^\\]+)+', re.IGNORECASE),
    }
    
    # Interesting keywords to flag
    INTERESTING_KEYWORDS = [
        'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
        'private', 'credential', 'login', 'auth', 'admin',
        'cmd.exe', 'powershell', 'bash', '/bin/sh',
        'wget', 'curl', 'nc ', 'netcat',
        'base64', 'decode', 'encrypt', 'decrypt',
        'socket', 'connect', 'bind', 'listen',
        'shell', 'exec', 'system', 'popen',
        'delete', 'remove', 'wipe', 'format',
        'ransom', 'bitcoin', 'wallet',
    ]
    
    def __init__(
        self,
        min_length: int = 4,
        encoding: str = 'both',
        interesting_only: bool = False
    ):
        """
        Initialize string extractor.
        
        Args:
            min_length: Minimum string length (default: 4)
            encoding: 'ascii', 'unicode', or 'both' (default: 'both')
            interesting_only: Only return strings matching patterns
        """
        self.min_length = min_length
        self.encoding = encoding
        self.interesting_only = interesting_only
    
    def extract(self, file_path: str, max_strings: int = 10000) -> StringExtractionResult:
        """
        Extract strings from a file.
        
        Args:
            file_path: Path to file
            max_strings: Maximum strings to extract
            
        Returns:
            StringExtractionResult
        """
        path = Path(file_path)
        result = StringExtractionResult(
            file_path=str(path.absolute()),
            file_size=0,
            total_strings=0
        )
        
        if not path.exists():
            result.error = "File not found"
            return result
        
        try:
            result.file_size = path.stat().st_size
            
            with open(path, 'rb') as f:
                data = f.read()
            
            strings = []
            
            # Extract ASCII strings
            if self.encoding in ('ascii', 'both'):
                ascii_strings = self._extract_ascii(data)
                strings.extend(ascii_strings)
            
            # Extract Unicode strings
            if self.encoding in ('unicode', 'both'):
                unicode_strings = self._extract_unicode(data)
                strings.extend(unicode_strings)
            
            # Sort by offset
            strings.sort(key=lambda x: x.offset)
            
            # Limit
            strings = strings[:max_strings]
            
            # Categorize
            self._categorize_strings(strings, result)
            
            if self.interesting_only:
                strings = [s for s in strings if s.category]
            
            result.strings = strings
            result.total_strings = len(strings)
            
        except PermissionError:
            result.error = "Permission denied"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _extract_ascii(self, data: bytes) -> List[ExtractedString]:
        """Extract ASCII printable strings."""
        strings = []
        current = []
        current_start = 0
        
        for i, byte in enumerate(data):
            # Printable ASCII range (32-126) plus tab, newline
            if 32 <= byte <= 126 or byte in (9, 10, 13):
                if not current:
                    current_start = i
                current.append(chr(byte))
            else:
                if len(current) >= self.min_length:
                    value = ''.join(current).strip()
                    if len(value) >= self.min_length:
                        strings.append(ExtractedString(
                            value=value,
                            offset=current_start,
                            encoding='ascii',
                            length=len(value)
                        ))
                current = []
        
        # Handle remaining
        if len(current) >= self.min_length:
            value = ''.join(current).strip()
            if len(value) >= self.min_length:
                strings.append(ExtractedString(
                    value=value,
                    offset=current_start,
                    encoding='ascii',
                    length=len(value)
                ))
        
        return strings
    
    def _extract_unicode(self, data: bytes) -> List[ExtractedString]:
        """Extract UTF-16 LE strings (common in Windows)."""
        strings = []
        
        # Look for UTF-16 LE patterns (char + null byte)
        i = 0
        while i < len(data) - 1:
            if data[i] != 0 and data[i + 1] == 0:
                # Potential UTF-16 LE string start
                chars = []
                start = i
                
                while i < len(data) - 1:
                    if 32 <= data[i] <= 126 and data[i + 1] == 0:
                        chars.append(chr(data[i]))
                        i += 2
                    elif data[i] in (9, 10, 13) and data[i + 1] == 0:
                        chars.append(chr(data[i]))
                        i += 2
                    else:
                        break
                
                if len(chars) >= self.min_length:
                    value = ''.join(chars).strip()
                    if len(value) >= self.min_length:
                        strings.append(ExtractedString(
                            value=value,
                            offset=start,
                            encoding='unicode',
                            length=len(value)
                        ))
            else:
                i += 1
        
        return strings
    
    def _categorize_strings(self, strings: List[ExtractedString], result: StringExtractionResult):
        """Categorize extracted strings."""
        seen_urls = set()
        seen_ips = set()
        seen_emails = set()
        seen_paths = set()
        seen_registry = set()
        seen_interesting = set()
        
        for s in strings:
            value = s.value
            
            # URLs
            for match in self.PATTERNS['url'].finditer(value):
                url = match.group()
                if url not in seen_urls:
                    seen_urls.add(url)
                    result.urls.append(url)
                s.category = 'url'
            
            # IPs
            for match in self.PATTERNS['ip'].finditer(value):
                ip = match.group()
                if ip not in seen_ips and not ip.startswith('0.') and not ip.startswith('127.'):
                    seen_ips.add(ip)
                    result.ips.append(ip)
                s.category = 'ip'
            
            # Emails
            for match in self.PATTERNS['email'].finditer(value):
                email = match.group()
                if email not in seen_emails:
                    seen_emails.add(email)
                    result.emails.append(email)
                s.category = 'email'
            
            # Paths
            for match in self.PATTERNS['windows_path'].finditer(value):
                path = match.group()
                if path not in seen_paths and len(path) > 5:
                    seen_paths.add(path)
                    result.paths.append(path)
                s.category = 'path'
            
            for match in self.PATTERNS['unix_path'].finditer(value):
                path = match.group()
                if path not in seen_paths and len(path) > 3 and path != '/':
                    seen_paths.add(path)
                    result.paths.append(path)
                s.category = 'path'
            
            # Registry
            for match in self.PATTERNS['registry'].finditer(value):
                key = match.group()
                if key not in seen_registry:
                    seen_registry.add(key)
                    result.registry_keys.append(key)
                s.category = 'registry'
            
            # Interesting keywords
            value_lower = value.lower()
            for keyword in self.INTERESTING_KEYWORDS:
                if keyword in value_lower:
                    if value not in seen_interesting:
                        seen_interesting.add(value)
                        result.interesting.append(value)
                    s.category = s.category or 'interesting'
                    break

