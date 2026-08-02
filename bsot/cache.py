"""
Caching layer for BSOT.
File-based cache with TTL support for API responses.
"""

import functools
import hashlib
import inspect
import json
import os
import time
from pathlib import Path
from typing import Optional, Any, Dict


class CacheManager:
    """
    Simple file-based cache with TTL support.
    
    Location: ~/.bsot/cache/
    Key: hash of (service_name + query)
    Value: JSON response + timestamp
    """
    
    DEFAULT_TTL_HOURS = 24
    CACHE_DIR = Path.home() / ".bsot" / "cache"
    
    # Service-specific TTL defaults (in hours)
    SERVICE_TTL = {
        "whois": 168,           # 7 days
        "virustotal": 24,       # 1 day
        "abuseipdb": 24,        # 1 day
        "geoip": 168,           # 7 days
        "dns": 24,              # 1 day
        "greynoise": 24,        # 1 day
        "otx": 24,              # 1 day
        "mitre": 720,           # 30 days
    }
    
    def __init__(self, cache_dir: Path = None):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Custom cache directory (default: ~/.bsot/cache/)
        """
        self.cache_dir = cache_dir or self.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.cache_dir, 0o700)
        except OSError:
            pass
    
    def _get_cache_key(self, service: str, query: str) -> str:
        """Generate cache key from service and query."""
        combined = f"{service}:{query}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def _get_cache_path(self, service: str, key: str) -> Path:
        """Get path to cache file."""
        service_dir = self.cache_dir / service
        service_dir.mkdir(parents=True, exist_ok=True)
        return service_dir / f"{key}.json"
    
    def get(self, service: str, query: str) -> Optional[Dict[str, Any]]:
        """
        Get cached data if valid (not expired).
        
        Args:
            service: Service name (virustotal, whois, etc.)
            query: The query/lookup key
            
        Returns:
            Cached data dict or None if not found/expired
        """
        key = self._get_cache_key(service, query)
        cache_path = self._get_cache_path(service, key)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                cached = json.load(f)
            
            # Check TTL
            cached_time = cached.get('_cached_at', 0)
            ttl_hours = cached.get('_ttl_hours', self.SERVICE_TTL.get(service, self.DEFAULT_TTL_HOURS))
            ttl_seconds = ttl_hours * 3600
            
            if time.time() - cached_time > ttl_seconds:
                # Expired, remove cache file
                cache_path.unlink(missing_ok=True)
                return None
            
            # Return data without metadata
            data = cached.copy()
            data.pop('_cached_at', None)
            data.pop('_ttl_hours', None)
            data.pop('_query', None)
            
            return data
            
        except (json.JSONDecodeError, IOError, KeyError):
            # Invalid cache file, remove it
            cache_path.unlink(missing_ok=True)
            return None
    
    def set(self, service: str, query: str, data: Dict[str, Any], ttl_hours: int = None):
        """
        Store data in cache.
        
        Args:
            service: Service name
            query: The query/lookup key
            data: Data to cache (must be JSON-serializable)
            ttl_hours: Time-to-live in hours (default: service-specific or 24)
        """
        if ttl_hours is None:
            ttl_hours = self.SERVICE_TTL.get(service, self.DEFAULT_TTL_HOURS)
        
        key = self._get_cache_key(service, query)
        cache_path = self._get_cache_path(service, key)
        
        # Add metadata
        cache_data = data.copy()
        cache_data['_cached_at'] = time.time()
        cache_data['_ttl_hours'] = ttl_hours
        cache_data['_query'] = query
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, default=str)
            # Cached lookups can contain investigation data; keep them private.
            os.chmod(cache_path, 0o600)
        except (IOError, TypeError, OSError):
            # Failed to write cache, not fatal
            pass
    
    def clear(self, service: str = None):
        """
        Clear cache.
        
        Args:
            service: Specific service to clear, or None for all
        """
        if service:
            service_dir = self.cache_dir / service
            if service_dir.exists():
                for cache_file in service_dir.glob("*.json"):
                    cache_file.unlink(missing_ok=True)
        else:
            # Clear all services
            for service_dir in self.cache_dir.iterdir():
                if service_dir.is_dir():
                    for cache_file in service_dir.glob("*.json"):
                        cache_file.unlink(missing_ok=True)
    
    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dict with cache stats per service
        """
        stats = {
            'total_entries': 0,
            'total_size_bytes': 0,
            'services': {}
        }
        
        for service_dir in self.cache_dir.iterdir():
            if service_dir.is_dir():
                service_name = service_dir.name
                files = list(service_dir.glob("*.json"))
                size = sum(f.stat().st_size for f in files)
                
                stats['services'][service_name] = {
                    'entries': len(files),
                    'size_bytes': size
                }
                stats['total_entries'] += len(files)
                stats['total_size_bytes'] += size
        
        return stats


# Global cache instance
cache = CacheManager()


def cached(service: str, ttl_hours: int = None):
    """
    Decorator for caching function results.
    
    The decorated function's first argument (after self if method) is used as the cache key.
    
    Usage:
        @cached("virustotal", ttl_hours=24)
        def lookup_ip(ip: str) -> dict:
            ...
    """
    def decorator(func):
        # Bound methods pass `self` first; the cache key is the argument after it.
        params = list(inspect.signature(func).parameters)
        key_index = 1 if params and params[0] in ('self', 'cls') else 0

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            no_cache = kwargs.pop('no_cache', False)

            if len(args) > key_index:
                query = args[key_index]
            elif params and len(params) > key_index:
                query = kwargs.get(params[key_index])
            else:
                query = None

            if query is not None and not no_cache:
                cached_result = cache.get(service, str(query))
                if cached_result is not None:
                    return cached_result

            result = func(*args, **kwargs)

            if query is not None and isinstance(result, dict):
                cache.set(service, str(query), result, ttl_hours)

            return result

        return wrapper
    return decorator



def from_cached(cls, data: Dict[str, Any]):
    """
    Rebuild a dataclass from a cached dict, ignoring unknown keys.

    Result classes expose derived values through to_dict() (is_malicious,
    latitude, score, ...) that are properties, not constructor parameters.
    Splatting a cached dict straight into the constructor therefore raises
    TypeError on every cache hit, so the keys are filtered to real fields.
    """
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in field_names})
