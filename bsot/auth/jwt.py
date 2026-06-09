"""
JWT Decoder and Analyzer
Decode and analyze JSON Web Tokens.
"""

import base64
import json
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class JWTAnalysis:
    """JWT analysis result."""
    token: str = ""  # Original token
    valid_format: bool = False
    
    # Decoded parts
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    
    # Algorithm
    algorithm: str = ""
    
    # Claims
    issuer: str = ""
    subject: str = ""
    audience: str = ""
    expiration: int = 0
    issued_at: int = 0
    not_before: int = 0
    jwt_id: str = ""
    
    # Expiration status
    is_expired: bool = False
    expires_in_seconds: int = 0
    expiration_human: str = ""
    
    # Security analysis
    vulnerabilities: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Signature verification
    signature_verified: bool = False
    
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'valid_format': self.valid_format,
            'header': self.header,
            'payload': self.payload,
            'algorithm': self.algorithm,
            'claims': {
                'issuer': self.issuer,
                'subject': self.subject,
                'audience': self.audience,
                'expiration': self.expiration,
                'issued_at': self.issued_at,
                'jwt_id': self.jwt_id,
            },
            'expiration': {
                'is_expired': self.is_expired,
                'expires_in_seconds': self.expires_in_seconds,
                'human': self.expiration_human,
            },
            'security': {
                'vulnerabilities': self.vulnerabilities,
                'warnings': self.warnings,
                'signature_verified': self.signature_verified,
            },
            'error': self.error,
        }


class JWTDecoder:
    """
    Decode and analyze JWT tokens.
    """
    
    # Weak algorithms
    WEAK_ALGORITHMS = ['none', 'HS256']  # HS256 is weak with short keys
    
    # Sensitive payload keys to warn about
    SENSITIVE_KEYS = ['password', 'secret', 'apikey', 'api_key', 'token', 'credit_card']
    
    def decode(self, token: str, verify_key: str = None) -> JWTAnalysis:
        """
        Decode and analyze a JWT token.
        
        Args:
            token: JWT token string
            verify_key: Optional key for signature verification
            
        Returns:
            JWTAnalysis result
        """
        result = JWTAnalysis(token=token)
        
        # Split token
        parts = token.split('.')
        if len(parts) != 3:
            result.error = f"Invalid JWT format: expected 3 parts, got {len(parts)}"
            return result
        
        try:
            # Decode header
            header_json = self._base64_decode(parts[0])
            result.header = json.loads(header_json)
            
            # Decode payload
            payload_json = self._base64_decode(parts[1])
            result.payload = json.loads(payload_json)
            
            # Signature (keep as-is)
            result.signature = parts[2]
            
            result.valid_format = True
            
        except json.JSONDecodeError as e:
            result.error = f"Invalid JSON in token: {e}"
            return result
        except Exception as e:
            result.error = f"Failed to decode token: {e}"
            return result
        
        # Extract algorithm
        result.algorithm = result.header.get('alg', 'unknown')
        
        # Extract standard claims
        result.issuer = result.payload.get('iss', '')
        result.subject = result.payload.get('sub', '')
        result.audience = result.payload.get('aud', '')
        result.expiration = result.payload.get('exp', 0)
        result.issued_at = result.payload.get('iat', 0)
        result.not_before = result.payload.get('nbf', 0)
        result.jwt_id = result.payload.get('jti', '')
        
        # Check expiration
        if result.expiration:
            now = int(time.time())
            result.expires_in_seconds = result.expiration - now
            result.is_expired = result.expires_in_seconds < 0
            
            if result.is_expired:
                result.expiration_human = f"Expired {-result.expires_in_seconds} seconds ago"
            elif result.expires_in_seconds < 3600:
                result.expiration_human = f"Expires in {result.expires_in_seconds} seconds"
            elif result.expires_in_seconds < 86400:
                result.expiration_human = f"Expires in {result.expires_in_seconds // 3600} hours"
            else:
                result.expiration_human = f"Expires in {result.expires_in_seconds // 86400} days"
        
        # Security analysis
        self._analyze_security(result)
        
        # Verify signature if key provided
        if verify_key:
            result.signature_verified = self._verify_signature(token, verify_key, result.algorithm)
        
        return result
    
    def _base64_decode(self, data: str) -> str:
        """Decode base64url encoded string."""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        # Replace URL-safe characters
        data = data.replace('-', '+').replace('_', '/')
        
        return base64.b64decode(data).decode('utf-8')
    
    def _analyze_security(self, result: JWTAnalysis):
        """Analyze token for security issues."""
        # Check algorithm
        if result.algorithm.lower() == 'none':
            result.vulnerabilities.append("Algorithm 'none' - token is not signed!")
        elif result.algorithm.lower() == 'hs256':
            result.warnings.append("HS256 may be vulnerable if key is weak or short")
        
        # Check for missing exp claim
        if not result.expiration:
            result.warnings.append("No expiration claim (exp) - token never expires")
        elif result.is_expired:
            result.vulnerabilities.append("Token is expired")
        
        # Check for missing iat claim
        if not result.issued_at:
            result.warnings.append("No issued-at claim (iat)")
        
        # Check for sensitive data in payload
        for key in result.payload.keys():
            if key.lower() in self.SENSITIVE_KEYS:
                result.vulnerabilities.append(f"Sensitive data in payload: {key}")
        
        # Check for very long expiration
        if result.expiration:
            exp_days = result.expires_in_seconds / 86400
            if exp_days > 365:
                result.warnings.append(f"Very long expiration: {int(exp_days)} days")
    
    def _verify_signature(self, token: str, key: str, algorithm: str) -> bool:
        """
        Verify JWT signature.
        
        Note: This is a basic implementation. For production, use PyJWT library.
        """
        import hmac
        import hashlib
        
        if algorithm.lower() == 'none':
            return False
        
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        message = f"{parts[0]}.{parts[1]}"
        signature = parts[2]
        
        try:
            if algorithm.upper() == 'HS256':
                expected = hmac.new(
                    key.encode(),
                    message.encode(),
                    hashlib.sha256
                ).digest()
                
                # Base64url encode
                expected_b64 = base64.urlsafe_b64encode(expected).decode().rstrip('=')
                
                return hmac.compare_digest(expected_b64, signature)
            
        except Exception:
            pass
        
        return False
    
    def quick_decode(self, token: str) -> Dict[str, Any]:
        """Quick decode - just return header and payload."""
        result = self.decode(token)
        return {
            'header': result.header,
            'payload': result.payload,
            'is_expired': result.is_expired,
        }

