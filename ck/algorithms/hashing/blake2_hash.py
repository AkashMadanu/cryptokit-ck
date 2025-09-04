"""
Blake2 hash algorithm implementations.
"""

import hashlib
from .base import HashAlgorithm


class Blake2bHash(HashAlgorithm):
    """
    Blake2b hash algorithm implementation.
    
    Blake2b is optimized for 64-bit platforms and provides
    high performance with strong security guarantees.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "Blake2b"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (512 bits = 64 bytes by default)."""
        return 64
    
    def _create_hash_object(self):
        """Create and return a new Blake2b hash object."""
        return hashlib.blake2b()


class Blake2sHash(HashAlgorithm):
    """
    Blake2s hash algorithm implementation.
    
    Blake2s is optimized for 32-bit platforms and provides
    good performance with strong security guarantees.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "Blake2s"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (256 bits = 32 bytes by default)."""
        return 32
    
    def _create_hash_object(self):
        """Create and return a new Blake2s hash object."""
        return hashlib.blake2s()
