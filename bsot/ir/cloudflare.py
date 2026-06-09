"""
Cloudflare Integration
Block IPs and manage firewall rules via Cloudflare API.
"""

import requests
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class CloudflareRule:
    """A Cloudflare access rule."""
    id: str
    mode: str  # block, challenge, whitelist, js_challenge, managed_challenge
    target: str  # ip, ip_range, country, asn
    value: str
    notes: str = ""
    created_on: str = ""
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'mode': self.mode,
            'target': self.target,
            'value': self.value,
            'notes': self.notes,
            'created_on': self.created_on,
        }


class CloudflareClient:
    """
    Cloudflare API client for IP blocking and firewall management.
    
    Supports:
    - IP Access Rules (block individual IPs or ranges)
    - Listing existing rules
    - Removing rules
    """
    
    BASE_URL = "https://api.cloudflare.com/client/v4"
    
    def __init__(self, api_token: str, zone_id: Optional[str] = None, account_id: Optional[str] = None):
        """
        Initialize Cloudflare client.
        
        Args:
            api_token: Cloudflare API token
            zone_id: Zone ID for zone-level rules
            account_id: Account ID for account-level rules
        """
        self.api_token = api_token
        self.zone_id = zone_id
        self.account_id = account_id
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
        })
    
    def _get_base_url(self) -> str:
        """Get the appropriate base URL for zone or account level."""
        if self.zone_id:
            return f"{self.BASE_URL}/zones/{self.zone_id}"
        elif self.account_id:
            return f"{self.BASE_URL}/accounts/{self.account_id}"
        else:
            raise ValueError("Either zone_id or account_id must be provided")
    
    def block_ip(
        self, 
        ip: str, 
        notes: str = "Blocked via BSOT IR",
        mode: str = "block"
    ) -> Dict[str, Any]:
        """
        Block an IP address or CIDR range.
        
        Args:
            ip: IP address (1.2.3.4) or CIDR range (1.2.3.0/24)
            notes: Note to attach to the rule
            mode: block, challenge, js_challenge, managed_challenge
            
        Returns:
            API response dict with rule details
        """
        # Determine if it's an IP or range
        target = "ip_range" if "/" in ip else "ip"
        
        url = f"{self._get_base_url()}/firewall/access_rules/rules"
        
        payload = {
            "mode": mode,
            "configuration": {
                "target": target,
                "value": ip
            },
            "notes": notes
        }
        
        response = self.session.post(url, json=payload)
        data = response.json()
        
        if not data.get('success'):
            errors = data.get('errors', [])
            error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            raise Exception(f"Cloudflare API error: {error_msg}")
        
        return {
            'success': True,
            'rule_id': data['result']['id'],
            'ip': ip,
            'mode': mode,
            'message': f"Successfully blocked {ip}"
        }
    
    def unblock_ip(self, rule_id: str) -> Dict[str, Any]:
        """
        Remove an IP block rule by ID.
        
        Args:
            rule_id: The rule ID to remove
            
        Returns:
            API response
        """
        url = f"{self._get_base_url()}/firewall/access_rules/rules/{rule_id}"
        
        response = self.session.delete(url)
        data = response.json()
        
        if not data.get('success'):
            errors = data.get('errors', [])
            error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            raise Exception(f"Cloudflare API error: {error_msg}")
        
        return {
            'success': True,
            'rule_id': rule_id,
            'message': f"Successfully removed rule {rule_id}"
        }
    
    def find_rule_by_ip(self, ip: str) -> Optional[CloudflareRule]:
        """
        Find an existing rule for an IP.
        
        Args:
            ip: IP address to search for
            
        Returns:
            CloudflareRule if found, None otherwise
        """
        rules = self.list_rules(search=ip)
        for rule in rules:
            if rule.value == ip:
                return rule
        return None
    
    def list_rules(
        self, 
        mode: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 50
    ) -> List[CloudflareRule]:
        """
        List IP access rules.
        
        Args:
            mode: Filter by mode (block, challenge, etc.)
            search: Search term (IP, notes, etc.)
            page: Page number
            per_page: Results per page
            
        Returns:
            List of CloudflareRule objects
        """
        url = f"{self._get_base_url()}/firewall/access_rules/rules"
        
        params = {
            'page': page,
            'per_page': per_page,
        }
        if mode:
            params['mode'] = mode
        if search:
            params['configuration.value'] = search
        
        response = self.session.get(url, params=params)
        data = response.json()
        
        if not data.get('success'):
            errors = data.get('errors', [])
            error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            raise Exception(f"Cloudflare API error: {error_msg}")
        
        rules = []
        for item in data.get('result', []):
            config = item.get('configuration', {})
            rules.append(CloudflareRule(
                id=item['id'],
                mode=item['mode'],
                target=config.get('target', ''),
                value=config.get('value', ''),
                notes=item.get('notes', ''),
                created_on=item.get('created_on', ''),
            ))
        
        return rules
    
    def bulk_block(
        self, 
        ips: List[str], 
        notes: str = "Blocked via BSOT IR"
    ) -> Dict[str, Any]:
        """
        Block multiple IPs.
        
        Args:
            ips: List of IP addresses
            notes: Note to attach to rules
            
        Returns:
            Summary of results
        """
        results = {
            'success': [],
            'failed': [],
            'skipped': [],
        }
        
        for ip in ips:
            try:
                # Check if already blocked
                existing = self.find_rule_by_ip(ip)
                if existing:
                    results['skipped'].append({
                        'ip': ip,
                        'reason': 'Already blocked',
                        'rule_id': existing.id
                    })
                    continue
                
                result = self.block_ip(ip, notes=notes)
                results['success'].append({
                    'ip': ip,
                    'rule_id': result['rule_id']
                })
            except Exception as e:
                results['failed'].append({
                    'ip': ip,
                    'error': str(e)
                })
        
        return results
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test API connection and permissions.
        
        Returns:
            Connection status and account info
        """
        try:
            # Try to verify token
            url = f"{self.BASE_URL}/user/tokens/verify"
            response = self.session.get(url)
            data = response.json()
            
            if data.get('success'):
                return {
                    'success': True,
                    'status': data['result']['status'],
                    'message': 'API token is valid'
                }
            else:
                return {
                    'success': False,
                    'message': 'API token verification failed'
                }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }

