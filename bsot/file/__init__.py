"""
BSOT File Analysis Module
File forensics, hashing, and security scanning.
"""

from .hasher import FileHasher, hash_file, hash_string
from .identifier import FileIdentifier, identify_file
from .strings import StringExtractor
from .entropy import EntropyAnalyzer

__all__ = [
    'FileHasher',
    'hash_file',
    'hash_string',
    'FileIdentifier',
    'identify_file',
    'StringExtractor',
    'EntropyAnalyzer',
]

