"""
BSOT Authentication Module
Password analysis, JWT decoding, SSH auditing.
"""

from .password import PasswordAnalyzer
from .jwt import JWTDecoder

__all__ = [
    'PasswordAnalyzer',
    'JWTDecoder',
]

