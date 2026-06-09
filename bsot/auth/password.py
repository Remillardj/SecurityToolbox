"""
Password Analyzer
Password strength analysis and breach checking.
"""

import math
import re
import hashlib
from typing import List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class PasswordAnalysis:
    """Password analysis result."""
    password: str = ""  # Masked or empty in output
    length: int = 0
    
    # Character classes
    has_uppercase: bool = False
    has_lowercase: bool = False
    has_digits: bool = False
    has_special: bool = False
    character_classes: int = 0
    
    # Entropy
    entropy: float = 0.0
    
    # Patterns detected
    patterns: List[str] = field(default_factory=list)
    common_words: List[str] = field(default_factory=list)
    
    # Strength
    strength: str = ""  # weak, fair, good, strong
    score: int = 0  # 0-100
    
    # Breach check
    breach_count: int = -1  # -1 = not checked, 0 = not found, >0 = found
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'length': self.length,
            'character_classes': self.character_classes,
            'has_uppercase': self.has_uppercase,
            'has_lowercase': self.has_lowercase,
            'has_digits': self.has_digits,
            'has_special': self.has_special,
            'entropy': round(self.entropy, 2),
            'patterns': self.patterns,
            'strength': self.strength,
            'score': self.score,
            'breach_count': self.breach_count,
            'recommendations': self.recommendations,
        }


class PasswordAnalyzer:
    """
    Analyze password strength and check for breaches.
    """
    
    # Common passwords (sample - in production, use a larger list)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
        'password1', 'password123', 'iloveyou', 'sunshine', 'princess',
    }
    
    # Common patterns
    PATTERNS = [
        (r'(.)\1{2,}', 'Repeated characters'),
        (r'(012|123|234|345|456|567|678|789|890)', 'Sequential numbers'),
        (r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl)', 'Sequential letters'),
        (r'(qwerty|asdf|zxcv)', 'Keyboard pattern'),
        (r'(19|20)\d{2}', 'Year pattern'),
        (r'(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])', 'Date pattern'),
    ]
    
    # L33t speak mappings
    LEET_MAP = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
    }
    
    def analyze(self, password: str, check_breach: bool = False) -> PasswordAnalysis:
        """
        Analyze password strength.
        
        Args:
            password: Password to analyze
            check_breach: Check against Have I Been Pwned
            
        Returns:
            PasswordAnalysis result
        """
        result = PasswordAnalysis(length=len(password))
        
        if not password:
            result.strength = 'weak'
            result.recommendations.append('Password cannot be empty')
            return result
        
        # Check character classes
        result.has_uppercase = bool(re.search(r'[A-Z]', password))
        result.has_lowercase = bool(re.search(r'[a-z]', password))
        result.has_digits = bool(re.search(r'\d', password))
        result.has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        result.character_classes = sum([
            result.has_uppercase,
            result.has_lowercase,
            result.has_digits,
            result.has_special,
        ])
        
        # Calculate entropy
        result.entropy = self._calculate_entropy(password)
        
        # Check patterns
        result.patterns = self._check_patterns(password)
        
        # Check for common passwords
        pw_lower = password.lower()
        if pw_lower in self.COMMON_PASSWORDS:
            result.patterns.append('Common password')
        
        # Check l33t speak
        deleet = self._deleet(password)
        if deleet.lower() in self.COMMON_PASSWORDS:
            result.patterns.append('L33t speak of common password')
        
        # Calculate score
        result.score = self._calculate_score(result)
        
        # Determine strength
        if result.score >= 80:
            result.strength = 'strong'
        elif result.score >= 60:
            result.strength = 'good'
        elif result.score >= 40:
            result.strength = 'fair'
        else:
            result.strength = 'weak'
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
        
        # Check breach
        if check_breach:
            result.breach_count = self._check_hibp(password)
            if result.breach_count > 0:
                result.recommendations.insert(0, f'Password found in {result.breach_count} data breaches!')
                result.strength = 'weak'
                result.score = min(result.score, 20)
        
        return result
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy."""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0.0
        
        return len(password) * math.log2(charset_size)
    
    def _check_patterns(self, password: str) -> List[str]:
        """Check for common patterns."""
        patterns = []
        
        for pattern, description in self.PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                patterns.append(description)
        
        return patterns
    
    def _deleet(self, password: str) -> str:
        """Convert l33t speak back to letters."""
        result = password
        for leet, letter in self.LEET_MAP.items():
            result = result.replace(leet, letter)
        return result
    
    def _calculate_score(self, result: PasswordAnalysis) -> int:
        """Calculate password score (0-100)."""
        score = 0
        
        # Length (up to 30 points)
        score += min(30, result.length * 2)
        
        # Character classes (up to 20 points)
        score += result.character_classes * 5
        
        # Entropy (up to 30 points)
        score += min(30, int(result.entropy / 2))
        
        # Penalties for patterns
        score -= len(result.patterns) * 10
        
        # Ensure 0-100 range
        return max(0, min(100, score))
    
    def _generate_recommendations(self, result: PasswordAnalysis) -> List[str]:
        """Generate recommendations for improving password."""
        recs = []
        
        if result.length < 12:
            recs.append('Use at least 12 characters')
        
        if not result.has_uppercase:
            recs.append('Add uppercase letters')
        
        if not result.has_lowercase:
            recs.append('Add lowercase letters')
        
        if not result.has_digits:
            recs.append('Add numbers')
        
        if not result.has_special:
            recs.append('Add special characters (!@#$%^&*)')
        
        if 'Common password' in result.patterns:
            recs.append('Avoid common passwords')
        
        if 'Keyboard pattern' in result.patterns:
            recs.append('Avoid keyboard patterns like qwerty')
        
        if result.character_classes < 3:
            recs.append('Use a mix of character types')
        
        return recs
    
    def _check_hibp(self, password: str) -> int:
        """
        Check password against Have I Been Pwned API.
        Uses k-anonymity model (only sends first 5 chars of hash).
        
        Returns:
            Number of times password appeared in breaches, or -1 on error
        """
        import requests
        
        # SHA1 hash of password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=10
            )
            
            if response.status_code != 200:
                return -1
            
            # Check if our suffix is in the results
            for line in response.text.splitlines():
                if ':' in line:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
            
            return 0  # Not found
            
        except Exception:
            return -1

