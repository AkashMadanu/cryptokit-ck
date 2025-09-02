"""
Abstract base classes and interfaces for CryptoKit (CK)

Defines the contracts that all cryptographic implementations must follow.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from pathlib import Path


class CryptographicAlgorithm(ABC):
    """
    Abstract base class for all cryptographic algorithms.
    
    Provides a common interface for encryption and decryption operations.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the algorithm name."""
        pass
    
    @property
    @abstractmethod
    def key_size(self) -> int:
        """Get the key size in bits."""
        pass
    
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Encrypt data with the given key.
        
        Args:
            data: Data to encrypt
            key: Encryption key
            **kwargs: Algorithm-specific parameters
            
        Returns:
            Encrypted data
        """
        pass
    
    @abstractmethod
    def decrypt(self, encrypted_data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Decrypt data with the given key.
        
        Args:
            encrypted_data: Data to decrypt
            key: Decryption key
            **kwargs: Algorithm-specific parameters
            
        Returns:
            Decrypted data
        """
        pass
    
    @abstractmethod
    def generate_key(self, password: str, salt: bytes, **kwargs) -> bytes:
        """
        Generate a key from a password and salt.
        
        Args:
            password: User password
            salt: Random salt
            **kwargs: Key derivation parameters
            
        Returns:
            Derived key
        """
        pass
    
    def validate_key(self, key: bytes) -> bool:
        """
        Validate that a key is appropriate for this algorithm.
        
        Args:
            key: Key to validate
            
        Returns:
            True if key is valid
        """
        return len(key) * 8 == self.key_size


class HashAlgorithm(ABC):
    """
    Abstract base class for all hash algorithms.
    
    Provides a common interface for hashing operations.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the algorithm name."""
        pass
    
    @property
    @abstractmethod
    def digest_size(self) -> int:
        """Get the digest size in bytes."""
        pass
    
    @abstractmethod
    def hash(self, data: bytes) -> str:
        """
        Compute hash of data.
        
        Args:
            data: Data to hash
            
        Returns:
            Hex-encoded hash digest
        """
        pass
    
    @abstractmethod
    def hash_file(self, file_path: Path, chunk_size: int = 65536) -> str:
        """
        Compute hash of a file.
        
        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read
            
        Returns:
            Hex-encoded hash digest
        """
        pass
    
    def verify(self, data: bytes, expected_hash: str) -> bool:
        """
        Verify data against expected hash.
        
        Args:
            data: Data to verify
            expected_hash: Expected hash value
            
        Returns:
            True if hash matches
        """
        computed_hash = self.hash(data)
        return computed_hash.lower() == expected_hash.lower()


class ExternalTool(ABC):
    """
    Abstract base class for external tool integrations.
    
    Provides a common interface for interacting with external programs.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the tool name."""
        pass
    
    @property
    @abstractmethod
    def executable_path(self) -> str:
        """Get the path to the executable."""
        pass
    
    @abstractmethod
    def check_availability(self) -> bool:
        """
        Check if the tool is available and functional.
        
        Returns:
            True if tool is available
        """
        pass
    
    @abstractmethod
    def get_version(self) -> Optional[str]:
        """
        Get the tool version.
        
        Returns:
            Version string or None if unavailable
        """
        pass
    
    @abstractmethod
    def execute(self, args: List[str], **kwargs) -> Dict[str, Any]:
        """
        Execute the tool with given arguments.
        
        Args:
            args: Command-line arguments
            **kwargs: Execution options
            
        Returns:
            Execution result dictionary
        """
        pass


class CrackingTool(ExternalTool):
    """
    Abstract base class for hash cracking tools.
    
    Extends ExternalTool with cracking-specific functionality.
    """
    
    @abstractmethod
    def crack_hash(
        self,
        hash_value: str,
        hash_type: str,
        attack_mode: str = "dictionary",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Attempt to crack a hash.
        
        Args:
            hash_value: Hash to crack
            hash_type: Type of hash (md5, sha1, etc.)
            attack_mode: Attack mode to use
            **kwargs: Tool-specific options
            
        Returns:
            Cracking result dictionary
        """
        pass
    
    @abstractmethod
    def estimate_time(
        self,
        hash_type: str,
        attack_mode: str,
        **kwargs
    ) -> Optional[float]:
        """
        Estimate cracking time in seconds.
        
        Args:
            hash_type: Type of hash
            attack_mode: Attack mode
            **kwargs: Estimation parameters
            
        Returns:
            Estimated time in seconds or None if unknown
        """
        pass


class SteganographyMethod(ABC):
    """
    Abstract base class for steganography methods.
    
    Provides a common interface for hiding and extracting data.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the method name."""
        pass
    
    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """Get list of supported file formats."""
        pass
    
    @abstractmethod
    def hide_data(
        self,
        cover_file: Path,
        secret_data: bytes,
        output_file: Path,
        password: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Hide data in a cover file.
        
        Args:
            cover_file: File to hide data in
            secret_data: Data to hide
            output_file: Output file with hidden data
            password: Optional password for encryption
            **kwargs: Method-specific options
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def extract_data(
        self,
        stego_file: Path,
        password: Optional[str] = None,
        **kwargs
    ) -> Optional[bytes]:
        """
        Extract hidden data from a file.
        
        Args:
            stego_file: File containing hidden data
            password: Optional password for decryption
            **kwargs: Method-specific options
            
        Returns:
            Extracted data or None if not found
        """
        pass
    
    @abstractmethod
    def calculate_capacity(self, cover_file: Path) -> int:
        """
        Calculate maximum data capacity for a cover file.
        
        Args:
            cover_file: Cover file to analyze
            
        Returns:
            Maximum capacity in bytes
        """
        pass


class MetadataExtractor(ABC):
    """
    Abstract base class for metadata extractors.
    
    Provides a common interface for extracting file metadata.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the extractor name."""
        pass
    
    @property
    @abstractmethod
    def supported_types(self) -> List[str]:
        """Get list of supported file types."""
        pass
    
    @abstractmethod
    def extract(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract metadata from a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Metadata dictionary
        """
        pass
    
    @abstractmethod
    def can_extract(self, file_path: Path) -> bool:
        """
        Check if this extractor can handle the given file.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if extractor can handle the file
        """
        pass


class ProgressCallback(ABC):
    """
    Abstract base class for progress callbacks.
    
    Allows operations to report progress to the user interface.
    """
    
    @abstractmethod
    def update(self, current: int, total: int, message: str = "") -> None:
        """
        Update progress.
        
        Args:
            current: Current progress value
            total: Total progress value
            message: Optional progress message
        """
        pass
    
    @abstractmethod
    def complete(self, message: str = "") -> None:
        """
        Mark operation as complete.
        
        Args:
            message: Optional completion message
        """
        pass
    
    @abstractmethod
    def error(self, message: str) -> None:
        """
        Report an error.
        
        Args:
            message: Error message
        """
        pass
