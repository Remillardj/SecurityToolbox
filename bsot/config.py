"""
Configuration management for BSOT.
Handles API keys, settings, and profiles from environment variables or config files.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import json


class Config:
    """
    Configuration manager for BSOT API keys and settings.
    
    Supports:
    - Environment variables (highest priority)
    - Named profiles (~/.bsot/profiles/{name}.json)
    - Default config (~/.bsot/config.json)
    """
    
    CONFIG_DIR = Path.home() / ".bsot"
    CONFIG_FILE = CONFIG_DIR / "config.json"
    PROFILES_DIR = CONFIG_DIR / "profiles"
    
    # Environment variable names
    ENV_VARS = {
        'openai_api_key': 'OPENAI_API_KEY',
        'anthropic_api_key': 'ANTHROPIC_API_KEY',
        'virustotal_api_key': 'VIRUSTOTAL_API_KEY',
        'abuseipdb_api_key': 'ABUSEIPDB_API_KEY',
        'urlscan_api_key': 'URLSCAN_API_KEY',
        'shodan_api_key': 'SHODAN_API_KEY',
        'greynoise_api_key': 'GREYNOISE_API_KEY',
        'otx_api_key': 'OTX_API_KEY',
        'ipinfo_api_key': 'IPINFO_API_KEY',
        'securitytrails_api_key': 'SECURITYTRAILS_API_KEY',
        'hibp_api_key': 'HIBP_API_KEY',
        'censys_api_id': 'CENSYS_API_ID',
        'censys_api_secret': 'CENSYS_API_SECRET',
        # Cloudflare
        'cloudflare_api_token': 'CLOUDFLARE_API_TOKEN',
        'cloudflare_zone_id': 'CLOUDFLARE_ZONE_ID',
        'cloudflare_account_id': 'CLOUDFLARE_ACCOUNT_ID',
        # Malware analysis services
        'hybrid_analysis_api_key': 'HYBRID_ANALYSIS_API_KEY',
        # Report module
        'report_llm_provider': 'BSOT_LLM_PROVIDER',
        'report_llm_model': 'BSOT_LLM_MODEL',
        'ollama_host': 'OLLAMA_HOST',
        'ollama_model': 'OLLAMA_MODEL',
    }
    
    def __init__(self, profile: str = None):
        """
        Initialize configuration.

        Args:
            profile: Profile name to load (default: 'default' or None for base config)
        """
        self.profile_name = profile
        self._base = self._load_file(self.CONFIG_FILE)
        self._profile = (
            self._load_file(self.PROFILES_DIR / f"{profile}.json") if profile else {}
        )
        # Effective view: profile overrides base. Writes go to one layer only,
        # so saving a profile never copies base keys into it.
        self._config = {**self._base, **self._profile}
    
    @staticmethod
    def _load_file(path: Path) -> dict:
        """Load one config file. A corrupt file warns rather than vanishing."""
        if not path.exists():
            return {}
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(
                f"Warning: config file {path} is not valid JSON ({e}); ignoring it.",
                file=sys.stderr,
            )
        except IOError as e:
            print(f"Warning: could not read config file {path}: {e}", file=sys.stderr)
        return {}
    
    def _save_config(self, profile: str = None):
        """Save one layer to disk (profile layer, or base config)."""
        if profile:
            self.PROFILES_DIR.mkdir(parents=True, exist_ok=True)
            config_path = self.PROFILES_DIR / f"{profile}.json"
            data = self._profile
        else:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            config_path = self.CONFIG_FILE
            data = self._base

        with open(config_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Secure the config file (Unix only)
        try:
            os.chmod(config_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows doesn't support chmod
    
    def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Get a configuration value.
        Priority: Environment variable > Profile > Base config > Default
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        # Check environment variable first
        env_var = self.ENV_VARS.get(key)
        if env_var:
            env_value = os.environ.get(env_var)
            if env_value:
                return env_value
        
        # Check config
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any, profile: str = None):
        """
        Set a configuration value and save.
        
        Args:
            key: Configuration key
            value: Value to set
            profile: Profile to save to (None for base config)
        """
        target = profile or self.profile_name
        if target:
            self._profile[key] = value
        else:
            self._base[key] = value
        self._config[key] = value
        self._save_config(target)
    
    def list_profiles(self) -> list:
        """List available profiles."""
        profiles = ['default']
        if self.PROFILES_DIR.exists():
            for f in self.PROFILES_DIR.glob("*.json"):
                profiles.append(f.stem)
        return sorted(set(profiles))
    
    def create_profile(self, name: str, copy_from: str = None):
        """
        Create a new profile.
        
        Args:
            name: Profile name
            copy_from: Optional profile to copy settings from
        """
        self.PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        profile_path = self.PROFILES_DIR / f"{name}.json"
        
        if copy_from:
            source_path = self.PROFILES_DIR / f"{copy_from}.json"
            if source_path.exists():
                with open(source_path, 'r') as f:
                    profile_config = json.load(f)
            else:
                profile_config = {}
        else:
            profile_config = {}
        
        with open(profile_path, 'w') as f:
            json.dump(profile_config, f, indent=2)
        
        try:
            os.chmod(profile_path, 0o600)
        except (OSError, AttributeError):
            pass
    
    def delete_profile(self, name: str):
        """Delete a profile."""
        profile_path = self.PROFILES_DIR / f"{name}.json"
        if profile_path.exists():
            profile_path.unlink()
    
    # Convenience properties for API keys
    @property
    def openai_api_key(self) -> Optional[str]:
        return self.get('openai_api_key')
    
    @property
    def anthropic_api_key(self) -> Optional[str]:
        return self.get('anthropic_api_key')
    
    @property
    def virustotal_api_key(self) -> Optional[str]:
        return self.get('virustotal_api_key')
    
    @property
    def abuseipdb_api_key(self) -> Optional[str]:
        return self.get('abuseipdb_api_key')
    
    @property
    def urlscan_api_key(self) -> Optional[str]:
        return self.get('urlscan_api_key')
    
    @property
    def shodan_api_key(self) -> Optional[str]:
        return self.get('shodan_api_key')
    
    @property
    def greynoise_api_key(self) -> Optional[str]:
        return self.get('greynoise_api_key')
    
    @property
    def otx_api_key(self) -> Optional[str]:
        return self.get('otx_api_key')
    
    @property
    def ipinfo_api_key(self) -> Optional[str]:
        return self.get('ipinfo_api_key')
    
    @property
    def securitytrails_api_key(self) -> Optional[str]:
        return self.get('securitytrails_api_key')
    
    @property
    def hibp_api_key(self) -> Optional[str]:
        return self.get('hibp_api_key')
    
    @property
    def censys_credentials(self) -> Optional[tuple]:
        api_id = self.get('censys_api_id')
        api_secret = self.get('censys_api_secret')
        if api_id and api_secret:
            return (api_id, api_secret)
        return None
    
    # Cloudflare properties
    @property
    def cloudflare_api_token(self) -> Optional[str]:
        return self.get('cloudflare_api_token')
    
    @property
    def cloudflare_zone_id(self) -> Optional[str]:
        return self.get('cloudflare_zone_id')
    
    @property
    def cloudflare_account_id(self) -> Optional[str]:
        return self.get('cloudflare_account_id')
    
    @property
    def hybrid_analysis_api_key(self) -> Optional[str]:
        return self.get('hybrid_analysis_api_key')
    
    # Report module settings
    @property
    def report_llm_provider(self) -> Optional[str]:
        return self.get('report_llm_provider', 'anthropic')
    
    @property
    def report_llm_model(self) -> Optional[str]:
        return self.get('report_llm_model')
    
    @property
    def ollama_host(self) -> Optional[str]:
        return self.get('ollama_host', 'http://localhost:11434')
    
    @property
    def ollama_model(self) -> Optional[str]:
        return self.get('ollama_model', 'llama3')
    
    # Any key containing one of these is treated as a secret and never
    # returned by get_settings().
    _SECRET_MARKERS = ('key', 'secret', 'token', 'password', 'credential')

    def get_settings(self) -> Dict[str, Any]:
        """Get all non-sensitive settings."""
        return {
            key: value
            for key, value in self._config.items()
            if not any(marker in key.lower() for marker in self._SECRET_MARKERS)
        }
    
    def has_api_key(self, service: str) -> bool:
        """Check if an API key is configured for a service."""
        key_name = f"{service}_api_key"
        return self.get(key_name) is not None


# Global config instance (default profile)
config = Config()


def get_config(profile: str = None) -> Config:
    """
    Get a Config instance for a specific profile.
    
    Args:
        profile: Profile name
        
    Returns:
        Config instance
    """
    if profile:
        return Config(profile=profile)
    return config
