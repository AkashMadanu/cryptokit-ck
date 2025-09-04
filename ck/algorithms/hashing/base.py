"""
Base class for hash algorithms in CryptoKit.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union, BinaryIO
import hashlib


class HashAlgorithm(ABC):
    """
    Abstract base class for hash algorithms.
    
    All hash algorithm implementations must inherit from this class
    and implement the required abstract methods.
    """
    
    def __init__(self):
        """Initialize the hash algorithm."""
        self._hash_obj = None
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of the hash algorithm."""
        pass
    
    @property
    @abstractmethod
    def digest_size(self) -> int:
        """Return the digest size in bytes."""
        pass
    
    @abstractmethod
    def _create_hash_object(self):
        """Create and return a new hash object."""
        pass
    
    def hash_data(self, data: bytes) -> str:
        """
        Hash raw bytes data.
        
        Args:
            data: Raw bytes to hash
            
        Returns:
            Hexadecimal hash string
        """
        hash_obj = self._create_hash_object()
        hash_obj.update(data)
        return hash_obj.hexdigest()
    
    def hash_file(self, file_path: Union[str, Path]) -> str:
        """
        Hash a file.
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            Hexadecimal hash string
            
        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        hash_obj = self._create_hash_object()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
        except IOError as e:
            raise IOError(f"Error reading file {file_path}: {e}")
        
        return hash_obj.hexdigest()
    
    def hash_directory(self, dir_path: Union[str, Path]) -> str:
        """
        Hash a directory by creating a hash of its structure and file metadata.
        This is non-recursive and creates an integrity hash of the directory itself.
        
        Args:
            dir_path: Path to the directory to hash
            
        Returns:
            Hexadecimal hash string
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            ValueError: If path is not a directory
        """
        dir_path = Path(dir_path)
        
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")
        
        if not dir_path.is_dir():
            raise ValueError(f"Path is not a directory: {dir_path}")
        
        hash_obj = self._create_hash_object()
        
        try:
            # Get directory contents and sort for consistent hashing
            entries = sorted(dir_path.iterdir(), key=lambda x: x.name)
            
            # Hash directory name
            hash_obj.update(dir_path.name.encode('utf-8'))
            
            # Hash each entry's metadata (name, type, size if file)
            for entry in entries:
                # Hash entry name
                hash_obj.update(entry.name.encode('utf-8'))
                
                # Hash entry type
                if entry.is_file():
                    hash_obj.update(b'FILE')
                    # Add file size for integrity
                    hash_obj.update(str(entry.stat().st_size).encode('utf-8'))
                elif entry.is_dir():
                    hash_obj.update(b'DIR')
                else:
                    hash_obj.update(b'OTHER')
                    
        except OSError as e:
            raise IOError(f"Error reading directory {dir_path}: {e}")
        
        return hash_obj.hexdigest()
    
    def hash_string(self, text: str, encoding: str = 'utf-8') -> str:
        """
        Hash a string.
        
        Args:
            text: String to hash
            encoding: Text encoding (default: utf-8)
            
        Returns:
            Hexadecimal hash string
        """
        return self.hash_data(text.encode(encoding))
    
    def __str__(self) -> str:
        """String representation of the hash algorithm."""
        return f"{self.name} Hash Algorithm"
    
    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"<{self.__class__.__name__}(name='{self.name}', digest_size={self.digest_size})>"
