"""
File Hasher
Multi-algorithm file hashing with streaming support.
"""

import hashlib
from pathlib import Path
from typing import Dict, List, Optional, BinaryIO
from dataclasses import dataclass, field


SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']
CHUNK_SIZE = 8192  # 8KB chunks for streaming


@dataclass
class HashResult:
    """Result of file hashing."""
    file_path: str
    file_name: str
    file_size: int
    hashes: Dict[str, str] = field(default_factory=dict)
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'hashes': self.hashes,
            'error': self.error,
        }


class FileHasher:
    """
    Calculate file hashes using multiple algorithms.
    
    Supports streaming for large files.
    """
    
    def __init__(self, algorithms: List[str] = None):
        """
        Initialize hasher.
        
        Args:
            algorithms: List of hash algorithms to use (default: ['sha256'])
        """
        if algorithms is None:
            algorithms = ['sha256']
        
        self.algorithms = []
        for algo in algorithms:
            algo = algo.lower()
            if algo == 'all':
                self.algorithms = SUPPORTED_ALGORITHMS.copy()
                break
            elif algo in SUPPORTED_ALGORITHMS:
                if algo not in self.algorithms:
                    self.algorithms.append(algo)
        
        if not self.algorithms:
            self.algorithms = ['sha256']
    
    def hash_file(self, file_path: str) -> HashResult:
        """
        Calculate hashes for a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            HashResult with calculated hashes
        """
        path = Path(file_path)
        result = HashResult(
            file_path=str(path.absolute()),
            file_name=path.name,
            file_size=0
        )
        
        if not path.exists():
            result.error = "File not found"
            return result
        
        if not path.is_file():
            result.error = "Path is not a file"
            return result
        
        try:
            result.file_size = path.stat().st_size
            
            # Initialize hash objects
            hashers = {algo: hashlib.new(algo) for algo in self.algorithms}
            
            # Read file in chunks
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    for hasher in hashers.values():
                        hasher.update(chunk)
            
            # Get digests
            result.hashes = {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
            
        except PermissionError:
            result.error = "Permission denied"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def hash_stream(self, stream: BinaryIO, size_hint: int = 0) -> Dict[str, str]:
        """
        Calculate hashes from a binary stream.
        
        Args:
            stream: Binary stream to hash
            size_hint: Optional size hint for progress
            
        Returns:
            Dict of algorithm -> hash
        """
        hashers = {algo: hashlib.new(algo) for algo in self.algorithms}
        
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
        
        return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
    
    def hash_bytes(self, data: bytes) -> Dict[str, str]:
        """
        Calculate hashes from bytes.
        
        Args:
            data: Bytes to hash
            
        Returns:
            Dict of algorithm -> hash
        """
        return {algo: hashlib.new(algo, data).hexdigest() for algo in self.algorithms}
    
    def hash_directory(self, dir_path: str, recursive: bool = True) -> List[HashResult]:
        """
        Hash all files in a directory.
        
        Args:
            dir_path: Directory path
            recursive: Include subdirectories
            
        Returns:
            List of HashResult
        """
        path = Path(dir_path)
        results = []
        
        if not path.exists() or not path.is_dir():
            return results
        
        pattern = '**/*' if recursive else '*'
        for file_path in path.glob(pattern):
            if file_path.is_file():
                results.append(self.hash_file(str(file_path)))
        
        return results
    
    def verify(self, file_path: str, expected_hash: str, algorithm: str = None) -> bool:
        """
        Verify file against expected hash.
        
        Args:
            file_path: Path to file
            expected_hash: Expected hash value
            algorithm: Hash algorithm (auto-detected from hash length if not provided)
            
        Returns:
            True if hash matches
        """
        # Auto-detect algorithm from hash length
        if not algorithm:
            hash_len = len(expected_hash)
            algo_map = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}
            algorithm = algo_map.get(hash_len)
            if not algorithm:
                return False
        
        # Calculate hash
        original_algos = self.algorithms
        self.algorithms = [algorithm]
        result = self.hash_file(file_path)
        self.algorithms = original_algos
        
        if result.error:
            return False
        
        calculated = result.hashes.get(algorithm, '')
        return calculated.lower() == expected_hash.lower()


def hash_file(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Quick function to hash a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm
        
    Returns:
        Hash string or empty string on error
    """
    hasher = FileHasher([algorithm])
    result = hasher.hash_file(file_path)
    return result.hashes.get(algorithm, '')


def hash_string(data: str, algorithm: str = 'sha256') -> str:
    """
    Quick function to hash a string.
    
    Args:
        data: String to hash
        algorithm: Hash algorithm
        
    Returns:
        Hash string
    """
    return hashlib.new(algorithm, data.encode()).hexdigest()

