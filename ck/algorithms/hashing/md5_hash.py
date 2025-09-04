"""
MD5 hash algorithm implementation.
"""

import hashlib
from .base import HashAlgorithm


class MD5Hash(HashAlgorithm):
    """
    MD5 hash algorithm implementation.
    
    Note: MD5 is cryptographically broken and should only be used
    for non-security purposes like checksums or data integrity verification.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "MD5"
    
    @property
    def digest_size(self) -> int:
        """Return the digest size in bytes (128 bits = 16 bytes)."""
        return 16
    
    def _create_hash_object(self):
        """Create and return a new MD5 hash object."""
        return hashlib.md5()
