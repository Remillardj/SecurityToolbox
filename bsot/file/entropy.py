"""
Entropy Analyzer
Calculate file entropy to detect packing/encryption.
"""

import math
from pathlib import Path
from typing import List, Tuple
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class EntropyResult:
    """Entropy analysis result."""
    file_path: str
    file_size: int
    
    # Overall entropy
    entropy: float = 0.0
    
    # Verdict
    verdict: str = ""  # low, normal, high
    is_suspicious: bool = False
    
    # Block analysis
    block_size: int = 0
    block_entropies: List[Tuple[int, float]] = field(default_factory=list)  # (offset, entropy)
    
    # Statistics
    min_entropy: float = 0.0
    max_entropy: float = 0.0
    avg_entropy: float = 0.0
    high_entropy_blocks: int = 0
    
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'file_path': self.file_path,
            'file_size': self.file_size,
            'entropy': self.entropy,
            'verdict': self.verdict,
            'is_suspicious': self.is_suspicious,
            'block_size': self.block_size,
            'min_entropy': self.min_entropy,
            'max_entropy': self.max_entropy,
            'avg_entropy': self.avg_entropy,
            'high_entropy_blocks': self.high_entropy_blocks,
            'error': self.error,
        }


class EntropyAnalyzer:
    """
    Calculate file entropy to detect encryption, packing, or obfuscation.
    
    Entropy scale (0-8):
    - 0-4: Low entropy (structured data, text)
    - 4-6: Normal entropy (typical binaries)
    - 6-7.5: Medium-high entropy (compressed data)
    - 7.5-8: High entropy (encrypted/random data)
    """
    
    # Entropy thresholds
    LOW_THRESHOLD = 5.0
    NORMAL_THRESHOLD = 7.0
    HIGH_THRESHOLD = 7.5
    
    def __init__(self, block_size: int = 256):
        """
        Initialize analyzer.
        
        Args:
            block_size: Block size for per-block analysis
        """
        self.block_size = block_size
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value (0-8)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze(self, file_path: str, analyze_blocks: bool = False) -> EntropyResult:
        """
        Analyze file entropy.
        
        Args:
            file_path: Path to file
            analyze_blocks: Calculate per-block entropy
            
        Returns:
            EntropyResult
        """
        path = Path(file_path)
        result = EntropyResult(
            file_path=str(path.absolute()),
            file_size=0,
            block_size=self.block_size
        )
        
        if not path.exists():
            result.error = "File not found"
            return result
        
        try:
            result.file_size = path.stat().st_size
            
            with open(path, 'rb') as f:
                data = f.read()
            
            if not data:
                result.error = "File is empty"
                return result
            
            # Calculate overall entropy
            result.entropy = self.calculate_entropy(data)
            
            # Determine verdict
            if result.entropy < self.LOW_THRESHOLD:
                result.verdict = "low"
                result.is_suspicious = False
            elif result.entropy < self.NORMAL_THRESHOLD:
                result.verdict = "normal"
                result.is_suspicious = False
            elif result.entropy < self.HIGH_THRESHOLD:
                result.verdict = "medium-high"
                result.is_suspicious = True
            else:
                result.verdict = "high"
                result.is_suspicious = True
            
            # Block analysis
            if analyze_blocks:
                self._analyze_blocks(data, result)
            
        except PermissionError:
            result.error = "Permission denied"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _analyze_blocks(self, data: bytes, result: EntropyResult):
        """Analyze entropy per block."""
        blocks = []
        entropies = []
        
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            if len(block) >= self.block_size // 2:  # Only analyze substantial blocks
                entropy = self.calculate_entropy(block)
                blocks.append((i, entropy))
                entropies.append(entropy)
        
        result.block_entropies = blocks
        
        if entropies:
            result.min_entropy = min(entropies)
            result.max_entropy = max(entropies)
            result.avg_entropy = sum(entropies) / len(entropies)
            result.high_entropy_blocks = sum(1 for e in entropies if e > self.HIGH_THRESHOLD)
    
    def visualize_entropy(self, result: EntropyResult, width: int = 60) -> str:
        """
        Create ASCII visualization of block entropy.
        
        Args:
            result: EntropyResult with block analysis
            width: Width of visualization
            
        Returns:
            ASCII visualization string
        """
        if not result.block_entropies:
            return "No block data available"
        
        lines = []
        lines.append(f"Entropy visualization (block size: {result.block_size} bytes)")
        lines.append("=" * width)
        
        # Scale blocks to fit width
        step = max(1, len(result.block_entropies) // width)
        
        for i in range(0, len(result.block_entropies), step):
            offset, entropy = result.block_entropies[i]
            
            # Create bar
            bar_length = int((entropy / 8.0) * (width - 20))
            
            # Color code (using ASCII art indicators)
            if entropy < self.LOW_THRESHOLD:
                indicator = "░"
            elif entropy < self.NORMAL_THRESHOLD:
                indicator = "▒"
            elif entropy < self.HIGH_THRESHOLD:
                indicator = "▓"
            else:
                indicator = "█"
            
            bar = indicator * bar_length
            lines.append(f"{offset:08x}: {bar} {entropy:.2f}")
        
        lines.append("=" * width)
        lines.append(f"Overall: {result.entropy:.2f}/8.0 ({result.verdict})")
        
        return "\n".join(lines)
    
    def is_likely_encrypted(self, file_path: str) -> bool:
        """
        Quick check if file is likely encrypted or packed.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if likely encrypted/packed
        """
        result = self.analyze(file_path)
        return result.entropy >= self.HIGH_THRESHOLD
    
    def is_likely_compressed(self, file_path: str) -> bool:
        """
        Quick check if file is likely compressed.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if likely compressed
        """
        result = self.analyze(file_path)
        return self.NORMAL_THRESHOLD <= result.entropy < self.HIGH_THRESHOLD

