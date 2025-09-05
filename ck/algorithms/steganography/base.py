"""
Base class for steganography algorithms in CryptoKit.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union, Optional, Tuple
import os


class SteganographyAlgorithm(ABC):
    """
    Abstract base class for steganography algorithms.
    
    All steganography algorithm implementations must inherit from this class
    and implement the required abstract methods.
    """
    
    def __init__(self):
        """Initialize the steganography algorithm."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of the steganography algorithm."""
        pass
    
    @property
    @abstractmethod
    def supported_formats(self) -> list:
        """Return list of supported file formats."""
        pass
    
    @abstractmethod
    def calculate_capacity(self, cover_file: Union[str, Path]) -> int:
        """
        Calculate the maximum number of bytes that can be hidden in the cover file.
        
        Args:
            cover_file: Path to the cover file
            
        Returns:
            Maximum capacity in bytes
            
        Raises:
            ValueError: If file format is not supported
            FileNotFoundError: If file doesn't exist
        """
        pass
    
    @abstractmethod
    def hide_data(self, 
                  cover_file: Union[str, Path],
                  secret_data: bytes,
                  output_file: Union[str, Path],
                  password: Optional[str] = None) -> bool:
        """
        Hide secret data in the cover file.
        
        Args:
            cover_file: Path to the cover file
            secret_data: Data to hide (as bytes)
            output_file: Path for the output file with hidden data
            password: Optional password for encryption
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            ValueError: If data is too large for cover file
            FileNotFoundError: If cover file doesn't exist
            IOError: If file operations fail
        """
        pass
    
    @abstractmethod
    def extract_data(self,
                     stego_file: Union[str, Path],
                     password: Optional[str] = None) -> bytes:
        """
        Extract hidden data from a steganography file.
        
        Args:
            stego_file: Path to the file containing hidden data
            password: Optional password for decryption
            
        Returns:
            Extracted data as bytes
            
        Raises:
            ValueError: If no hidden data found or wrong password
            FileNotFoundError: If file doesn't exist
            IOError: If file operations fail
        """
        pass
    
    def validate_cover_file(self, cover_file: Union[str, Path]) -> bool:
        """
        Validate if the cover file is suitable for this algorithm.
        
        Args:
            cover_file: Path to the cover file
            
        Returns:
            True if file is valid, False otherwise
        """
        cover_file = Path(cover_file)
        
        # Check if file exists
        if not cover_file.exists():
            return False
        
        # Check if it's a file (not directory)
        if not cover_file.is_file():
            return False
        
        # Check file extension
        ext = cover_file.suffix.lower()
        if ext not in self.supported_formats:
            return False
        
        return True
    
    def prepare_secret_data(self, 
                           secret_data: bytes, 
                           password: Optional[str] = None) -> bytes:
        """
        Prepare secret data for hiding (optionally encrypt).
        
        Args:
            secret_data: Raw secret data
            password: Optional password for encryption
            
        Returns:
            Prepared data (encrypted if password provided)
        """
        if password:
            # Simple XOR encryption for now (can be enhanced later)
            key = self._generate_key_from_password(password)
            encrypted_data = self._xor_encrypt(secret_data, key)
            # Add a simple header to indicate encryption
            return b"CK_ENCRYPTED:" + encrypted_data
        else:
            # Add header to indicate no encryption
            return b"CK_PLAIN:" + secret_data
    
    def recover_secret_data(self, 
                           extracted_data: bytes, 
                           password: Optional[str] = None) -> bytes:
        """
        Recover secret data from extracted data (optionally decrypt).
        
        Args:
            extracted_data: Data extracted from stego file
            password: Optional password for decryption
            
        Returns:
            Original secret data
            
        Raises:
            ValueError: If data format is invalid or wrong password
        """
        if extracted_data.startswith(b"CK_ENCRYPTED:"):
            if not password:
                raise ValueError("Password required to decrypt hidden data")
            
            encrypted_data = extracted_data[13:]  # Remove "CK_ENCRYPTED:" header
            key = self._generate_key_from_password(password)
            return self._xor_encrypt(encrypted_data, key)  # XOR is symmetric
            
        elif extracted_data.startswith(b"CK_PLAIN:"):
            return extracted_data[9:]  # Remove "CK_PLAIN:" header
            
        else:
            raise ValueError("Invalid or corrupted hidden data format")
    
    def _generate_key_from_password(self, password: str) -> bytes:
        """Generate encryption key from password."""
        # Simple key derivation (can be enhanced with PBKDF2 later)
        key = password.encode('utf-8')
        # Repeat key to make it longer if needed
        while len(key) < 32:
            key += key
        return key[:32]  # Use first 32 bytes
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption."""
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
    
    def get_file_size(self, file_path: Union[str, Path]) -> int:
        """Get file size in bytes."""
        return os.path.getsize(file_path)
    
    def __str__(self) -> str:
        """String representation of the steganography algorithm."""
        return f"{self.name} Steganography Algorithm"
    
    def __repr__(self) -> str:
        """Detailed string representation."""
        formats = ', '.join(self.supported_formats)
        return f"<{self.__class__.__name__}(name='{self.name}', formats=[{formats}])>"
