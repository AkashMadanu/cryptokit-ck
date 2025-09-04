"""
Hashing algorithms module for CryptoKit.

This module provides implementations of various cryptographic hash functions
including MD5, SHA family, and Blake2 variants.
"""

from .base import HashAlgorithm
from .md5_hash import MD5Hash
from .sha_hash import SHA1Hash, SHA256Hash, SHA384Hash, SHA512Hash
from .blake2_hash import Blake2bHash, Blake2sHash

__all__ = [
    'HashAlgorithm',
    'MD5Hash',
    'SHA1Hash', 
    'SHA256Hash',
    'SHA384Hash',
    'SHA512Hash',
    'Blake2bHash',
    'Blake2sHash'
]

# Algorithm registry for easy access
HASH_ALGORITHMS = {
    'md5': MD5Hash,
    'sha1': SHA1Hash,
    'sha256': SHA256Hash,
    'sha384': SHA384Hash,
    'sha512': SHA512Hash,
    'blake2b': Blake2bHash,
    'blake2s': Blake2sHash,
}

def get_hash_algorithm(name: str) -> type:
    """
    Get hash algorithm class by name.
    
    Args:
        name: Algorithm name (md5, sha1, sha256, etc.)
        
    Returns:
        Hash algorithm class
        
    Raises:
        ValueError: If algorithm not found
    """
    name = name.lower()
    if name not in HASH_ALGORITHMS:
        available = ', '.join(HASH_ALGORITHMS.keys())
        raise ValueError(f"Hash algorithm '{name}' not supported. Available: {available}")
    
    return HASH_ALGORITHMS[name]

def list_hash_algorithms() -> list:
    """Get list of available hash algorithm names."""
    return list(HASH_ALGORITHMS.keys())
