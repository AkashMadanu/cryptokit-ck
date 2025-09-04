"""
SHA family hash algorithm implementations.
"""

import hashlib
from .base import HashAlgorithm


class SHA1Hash(HashAlgorithm):
    """
    SHA-1 hash algorithm implementation.
    
    Note: SHA-1 is considered weak and should only be used
    for compatibility with legacy systems.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "SHA-1"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (160 bits = 20 bytes)."""
        return 20
    
    def _create_hash_object(self):
        """Create and return a new SHA-1 hash object."""
        return hashlib.sha1()


class SHA256Hash(HashAlgorithm):
    """
    SHA-256 hash algorithm implementation.
    
    SHA-256 is part of the SHA-2 family and is widely used
    for cryptographic applications.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "SHA-256"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (256 bits = 32 bytes)."""
        return 32
    
    def _create_hash_object(self):
        """Create and return a new SHA-256 hash object."""
        return hashlib.sha256()


class SHA384Hash(HashAlgorithm):
    """
    SHA-384 hash algorithm implementation.
    
    SHA-384 is part of the SHA-2 family and provides
    increased security compared to SHA-256.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "SHA-384"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (384 bits = 48 bytes)."""
        return 48
    
    def _create_hash_object(self):
        """Create and return a new SHA-384 hash object."""
        return hashlib.sha384()


class SHA512Hash(HashAlgorithm):
    """
    SHA-512 hash algorithm implementation.
    
    SHA-512 is part of the SHA-2 family and provides
    the highest security level in the SHA-2 family.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "SHA-512"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (512 bits = 64 bytes)."""
        return 64
    
    def _create_hash_object(self):
        """Create and return a new SHA-512 hash object."""
        return hashlib.sha512()
