"""
IOC Store
Manages consolidated IOCs for a case.
"""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict


@dataclass
class IOC:
    """Represents an Indicator of Compromise."""
    type: str  # ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, file_path, registry, mutex, crypto_wallet
    value: str
    source: str  # command/module that found it
    confidence: str  # low, medium, high
    context: str  # additional context
    first_seen: str
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'IOC':
        return cls(
            type=data.get('type', 'unknown'),
            value=data.get('value', ''),
            source=data.get('source', ''),
            confidence=data.get('confidence', 'medium'),
            context=data.get('context', ''),
            first_seen=data.get('first_seen', ''),
            tags=data.get('tags', []),
        )


class IOCStore:
    """
    Manages IOCs for a case with deduplication and validation.
    """
    
    # IOC validation patterns
    PATTERNS = {
        'ip': re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ),
        'domain': re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ),
        'url': re.compile(r'^https?://'),
        'hash_md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'hash_sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'hash_sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'email': re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'),
    }
    
    def __init__(self, ioc_file: Path):
        """
        Initialize IOC store.
        
        Args:
            ioc_file: Path to iocs.json file
        """
        self.ioc_file = Path(ioc_file)
        self.iocs: List[IOC] = []
        self._seen: Set[str] = set()
        
        self._load()
    
    def _load(self):
        """Load IOCs from file."""
        if self.ioc_file.exists():
            try:
                data = json.loads(self.ioc_file.read_text())
                if isinstance(data, list):
                    for item in data:
                        ioc = IOC.from_dict(item)
                        self.iocs.append(ioc)
                        self._seen.add(self._make_key(ioc.type, ioc.value))
            except Exception:
                pass
    
    def save(self):
        """Save IOCs to file."""
        data = [ioc.to_dict() for ioc in self.iocs]
        self.ioc_file.write_text(json.dumps(data, indent=2))
    
    def add(
        self,
        ioc_type: str,
        value: str,
        source: str = 'manual',
        confidence: str = 'medium',
        context: str = '',
        tags: List[str] = None
    ) -> bool:
        """
        Add an IOC to the store.
        
        Args:
            ioc_type: Type of IOC
            value: IOC value
            source: Source that found the IOC
            confidence: Confidence level
            context: Additional context
            tags: Tags for the IOC
            
        Returns:
            True if added, False if duplicate
        """
        # Normalize value
        value = value.strip()
        if not value:
            return False
        
        # Normalize type
        ioc_type = self._normalize_type(ioc_type, value)
        
        # Check for duplicate
        key = self._make_key(ioc_type, value)
        if key in self._seen:
            return False
        
        # Validate if possible
        if not self._validate(ioc_type, value):
            return False
        
        # Create IOC
        ioc = IOC(
            type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            context=context,
            first_seen=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            tags=tags or [],
        )
        
        self.iocs.append(ioc)
        self._seen.add(key)
        
        return True
    
    def add_bulk(self, iocs: List[Dict[str, Any]]) -> int:
        """
        Add multiple IOCs.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            Number of IOCs added
        """
        count = 0
        for ioc_data in iocs:
            if self.add(
                ioc_type=ioc_data.get('type', 'unknown'),
                value=ioc_data.get('value', ''),
                source=ioc_data.get('source', 'bulk'),
                confidence=ioc_data.get('confidence', 'medium'),
                context=ioc_data.get('context', ''),
                tags=ioc_data.get('tags'),
            ):
                count += 1
        return count
    
    def get_by_type(self, ioc_type: str) -> List[IOC]:
        """Get IOCs of a specific type."""
        return [ioc for ioc in self.iocs if ioc.type == ioc_type]
    
    def get_by_confidence(self, confidence: str) -> List[IOC]:
        """Get IOCs with a specific confidence level."""
        return [ioc for ioc in self.iocs if ioc.confidence == confidence]
    
    def get_all(self) -> List[IOC]:
        """Get all IOCs."""
        return self.iocs.copy()
    
    def count(self) -> int:
        """Get total IOC count."""
        return len(self.iocs)
    
    def count_by_type(self) -> Dict[str, int]:
        """Get IOC counts by type."""
        counts = {}
        for ioc in self.iocs:
            counts[ioc.type] = counts.get(ioc.type, 0) + 1
        return counts
    
    def clear(self):
        """Clear all IOCs."""
        self.iocs = []
        self._seen = set()
    
    def to_stix(self) -> dict:
        """Export IOCs as STIX 2.1 bundle."""
        import uuid as uuid_lib
        
        objects = []
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        for ioc in self.iocs:
            pattern = self._to_stix_pattern(ioc)
            if not pattern:
                continue
            
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{uuid_lib.uuid4()}',
                'created': now,
                'modified': now,
                'name': f'{ioc.type}: {ioc.value[:50]}',
                'pattern': pattern,
                'pattern_type': 'stix',
                'indicator_types': ['malicious-activity'],
                'valid_from': ioc.first_seen or now,
                'confidence': {'low': 25, 'medium': 50, 'high': 75}.get(ioc.confidence, 50),
            }
            
            if ioc.context:
                indicator['description'] = ioc.context
            
            objects.append(indicator)
        
        return {
            'type': 'bundle',
            'id': f'bundle--{uuid_lib.uuid4()}',
            'objects': objects,
        }
    
    def to_csv(self) -> str:
        """Export IOCs as CSV."""
        lines = ['type,value,source,confidence,context,first_seen,tags']
        
        for ioc in self.iocs:
            tags_str = ';'.join(ioc.tags) if ioc.tags else ''
            # Escape quotes and commas
            value = ioc.value.replace('"', '""')
            context = ioc.context.replace('"', '""')
            lines.append(f'{ioc.type},"{value}",{ioc.source},{ioc.confidence},"{context}",{ioc.first_seen},"{tags_str}"')
        
        return '\n'.join(lines)
    
    def to_misp(self) -> List[dict]:
        """Export IOCs as MISP format."""
        misp_objects = []
        
        type_map = {
            'ip': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'hash_md5': 'md5',
            'hash_sha1': 'sha1',
            'hash_sha256': 'sha256',
            'email': 'email-src',
            'file_path': 'filename',
            'registry': 'regkey',
        }
        
        for ioc in self.iocs:
            misp_type = type_map.get(ioc.type, 'text')
            misp_objects.append({
                'type': misp_type,
                'value': ioc.value,
                'comment': ioc.context,
                'to_ids': True,
            })
        
        return misp_objects
    
    def _make_key(self, ioc_type: str, value: str) -> str:
        """Create a unique key for deduplication."""
        return f"{ioc_type}:{value.lower()}"
    
    def _normalize_type(self, ioc_type: str, value: str) -> str:
        """Normalize and potentially auto-detect IOC type."""
        ioc_type = ioc_type.lower()
        
        # Auto-detect hash type
        if ioc_type == 'hash':
            if len(value) == 32:
                return 'hash_md5'
            elif len(value) == 40:
                return 'hash_sha1'
            elif len(value) == 64:
                return 'hash_sha256'
        
        return ioc_type
    
    def _validate(self, ioc_type: str, value: str) -> bool:
        """Validate IOC format."""
        pattern = self.PATTERNS.get(ioc_type)
        if pattern:
            return bool(pattern.match(value))
        return True  # Accept unknown types
    
    def _to_stix_pattern(self, ioc: IOC) -> Optional[str]:
        """Convert IOC to STIX pattern."""
        value = ioc.value.replace("'", "\\'")
        
        patterns = {
            'ip': f"[ipv4-addr:value = '{value}']",
            'domain': f"[domain-name:value = '{value}']",
            'url': f"[url:value = '{value}']",
            'hash_md5': f"[file:hashes.'MD5' = '{value}']",
            'hash_sha1': f"[file:hashes.'SHA-1' = '{value}']",
            'hash_sha256': f"[file:hashes.'SHA-256' = '{value}']",
            'email': f"[email-addr:value = '{value}']",
            'file_path': f"[file:name = '{value}']",
            'registry': f"[windows-registry-key:key = '{value}']",
        }
        
        return patterns.get(ioc.type)


