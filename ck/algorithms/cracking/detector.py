"""
Hash type detection for CryptoKit (CK)

Simple pattern-based hash format detection using regular expressions
and length analysis.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class HashMatch:
    """Represents a potential hash match with confidence score."""
    hash_type: str
    confidence: float
    description: str
    bit_length: int


class HashDetector:
    """
    Simple hash type detector using pattern matching.
    
    Detects common hash formats based on length and character patterns.
    """
    
    # Hash format patterns with their characteristics
    HASH_PATTERNS = {
        'md5': {
            'pattern': r'^[a-fA-F0-9]{32}$',
            'length': 32,
            'description': 'MD5 (128-bit)',
            'bit_length': 128
        },
        'sha1': {
            'pattern': r'^[a-fA-F0-9]{40}$',
            'length': 40,
            'description': 'SHA-1 (160-bit)',
            'bit_length': 160
        },
        'sha256': {
            'pattern': r'^[a-fA-F0-9]{64}$',
            'length': 64,
            'description': 'SHA-256 (256-bit)',
            'bit_length': 256
        },
        'sha384': {
            'pattern': r'^[a-fA-F0-9]{96}$',
            'length': 96,
            'description': 'SHA-384 (384-bit)',
            'bit_length': 384
        },
        'sha512': {
            'pattern': r'^[a-fA-F0-9]{128}$',
            'length': 128,
            'description': 'SHA-512 (512-bit)',
            'bit_length': 512
        },
        'blake2b': {
            'pattern': r'^[a-fA-F0-9]{128}$',
            'length': 128,
            'description': 'Blake2b (512-bit)',
            'bit_length': 512
        },
        'blake2s': {
            'pattern': r'^[a-fA-F0-9]{64}$',
            'length': 64,
            'description': 'Blake2s (256-bit)',
            'bit_length': 256
        }
    }
    
    def detect_hash_type(self, hash_value: str) -> List[HashMatch]:
        """
        Detect possible hash types for a given hash value.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            List of possible hash matches with confidence scores
        """
        if not hash_value:
            return []
        
        # Clean the hash value
        hash_value = hash_value.strip()
        
        matches = []
        
        for hash_type, info in self.HASH_PATTERNS.items():
            if re.match(info['pattern'], hash_value):
                # Calculate confidence based on pattern specificity
                confidence = self._calculate_confidence(hash_value, hash_type, info)
                
                match = HashMatch(
                    hash_type=hash_type,
                    confidence=confidence,
                    description=info['description'],
                    bit_length=info['bit_length']
                )
                matches.append(match)
        
        # Sort by confidence (highest first)
        matches.sort(key=lambda x: x.confidence, reverse=True)
        
        return matches
    
    def get_most_likely_type(self, hash_value: str) -> Optional[HashMatch]:
        """
        Get the most likely hash type for a given hash value.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            Most likely hash match or None if no matches
        """
        matches = self.detect_hash_type(hash_value)
        return matches[0] if matches else None
    
    def _calculate_confidence(self, hash_value: str, hash_type: str, info: Dict) -> float:
        """
        Calculate confidence score for a hash match.
        
        Args:
            hash_value: The hash string
            hash_type: Type of hash being checked
            info: Hash type information
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 0.8  # Base confidence for pattern match
        
        # Bonus for unique lengths
        length_bonus = 0.0
        length_counts = {}
        for ht, ht_info in self.HASH_PATTERNS.items():
            length = ht_info['length']
            length_counts[length] = length_counts.get(length, 0) + 1
        
        current_length = info['length']
        if length_counts[current_length] == 1:
            length_bonus = 0.2  # Unique length gets bonus
        
        # Character distribution analysis
        char_bonus = self._analyze_character_distribution(hash_value)
        
        total_confidence = min(1.0, base_confidence + length_bonus + char_bonus)
        
        return total_confidence
    
    def _analyze_character_distribution(self, hash_value: str) -> float:
        """
        Analyze character distribution to improve confidence.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            Bonus confidence based on character distribution
        """
        if not hash_value:
            return 0.0
        
        # Count character types
        digits = sum(1 for c in hash_value if c.isdigit())
        letters = sum(1 for c in hash_value if c.isalpha())
        
        total_chars = len(hash_value)
        
        # Good distribution of digits and letters indicates a real hash
        digit_ratio = digits / total_chars
        letter_ratio = letters / total_chars
        
        # Ideal distribution is roughly balanced
        if 0.3 <= digit_ratio <= 0.7 and 0.3 <= letter_ratio <= 0.7:
            return 0.1
        
        return 0.0
    
    def is_valid_hash_format(self, hash_value: str) -> bool:
        """
        Check if a string matches any known hash format.
        
        Args:
            hash_value: String to check
            
        Returns:
            True if matches a known hash format
        """
        return len(self.detect_hash_type(hash_value)) > 0
    
    def get_supported_types(self) -> List[str]:
        """
        Get list of supported hash types.
        
        Returns:
            List of supported hash type names
        """
        return list(self.HASH_PATTERNS.keys())
