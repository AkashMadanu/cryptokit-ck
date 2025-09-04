"""
Hashing service for CryptoKit.

This module provides high-level hashing operations including
file hashing, directory hashing, and hash file management.
"""

from pathlib import Path
from typing import Union, Tuple
import logging

from ck.algorithms.hashing import get_hash_algorithm, list_hash_algorithms
from ck.core.exceptions import CKError


class HashingService:
    """
    High-level hashing service providing file and directory hashing capabilities.
    """
    
    def __init__(self):
        """Initialize the hashing service."""
        self.logger = logging.getLogger('ck.hashing')
    
    def hash_file(self, 
                  file_path: Union[str, Path], 
                  algorithm: str, 
                  save_to_file: bool = True) -> Tuple[str, Path]:
        """
        Hash a file using the specified algorithm.
        
        Args:
            file_path: Path to the file to hash
            algorithm: Hash algorithm name (md5, sha256, etc.)
            save_to_file: Whether to save hash to a file (default: True)
            
        Returns:
            Tuple of (hash_value, hash_file_path)
            
        Raises:
            CKError: If hashing fails
        """
        try:
            file_path = Path(file_path)
            
            # Validate input file
            if not file_path.exists():
                raise CKError(f"File not found: {file_path}")
            
            if not file_path.is_file():
                raise CKError(f"Path is not a file: {file_path}")
            
            # Get algorithm instance
            try:
                algo_class = get_hash_algorithm(algorithm)
                algo_instance = algo_class()
            except ValueError as e:
                raise CKError(f"Invalid algorithm: {e}")
            
            self.logger.info(f"Hashing file {file_path} with {algo_instance.name}")
            
            # Calculate hash
            hash_value = algo_instance.hash_file(file_path)
            
            # Generate hash file path
            file_stem = file_path.stem  # filename without extension
            hash_file_path = file_path.parent / f"{file_stem}Hash.txt"
            
            # Save hash to file if requested
            if save_to_file:
                self._save_hash_to_file(
                    hash_value=hash_value,
                    algorithm=algo_instance.name,
                    source_path=file_path,
                    hash_file_path=hash_file_path
                )
            
            self.logger.info(f"File hashing completed: {hash_value}")
            
            return hash_value, hash_file_path
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"File hashing failed: {e}")
    
    def hash_directory(self, 
                      dir_path: Union[str, Path], 
                      algorithm: str, 
                      save_to_file: bool = True) -> Tuple[str, Path]:
        """
        Hash a directory using the specified algorithm.
        
        Args:
            dir_path: Path to the directory to hash
            algorithm: Hash algorithm name (md5, sha256, etc.)
            save_to_file: Whether to save hash to a file (default: True)
            
        Returns:
            Tuple of (hash_value, hash_file_path)
            
        Raises:
            CKError: If hashing fails
        """
        try:
            dir_path = Path(dir_path)
            
            # Validate input directory
            if not dir_path.exists():
                raise CKError(f"Directory not found: {dir_path}")
            
            if not dir_path.is_dir():
                raise CKError(f"Path is not a directory: {dir_path}")
            
            # Get algorithm instance
            try:
                algo_class = get_hash_algorithm(algorithm)
                algo_instance = algo_class()
            except ValueError as e:
                raise CKError(f"Invalid algorithm: {e}")
            
            self.logger.info(f"Hashing directory {dir_path} with {algo_instance.name}")
            
            # Calculate hash
            hash_value = algo_instance.hash_directory(dir_path)
            
            # Generate hash file path
            dir_name = dir_path.name
            hash_file_path = dir_path.parent / f"{dir_name}Hash.txt"
            
            # Save hash to file if requested
            if save_to_file:
                self._save_hash_to_file(
                    hash_value=hash_value,
                    algorithm=algo_instance.name,
                    source_path=dir_path,
                    hash_file_path=hash_file_path
                )
            
            self.logger.info(f"Directory hashing completed: {hash_value}")
            
            return hash_value, hash_file_path
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Directory hashing failed: {e}")
    
    def hash_string(self, 
                   text: str, 
                   algorithm: str, 
                   encoding: str = 'utf-8') -> str:
        """
        Hash a string using the specified algorithm.
        
        Args:
            text: String to hash
            algorithm: Hash algorithm name (md5, sha256, etc.)
            encoding: Text encoding (default: utf-8)
            
        Returns:
            Hash value as hexadecimal string
            
        Raises:
            CKError: If hashing fails
        """
        try:
            # Get algorithm instance
            try:
                algo_class = get_hash_algorithm(algorithm)
                algo_instance = algo_class()
            except ValueError as e:
                raise CKError(f"Invalid algorithm: {e}")
            
            self.logger.info(f"Hashing string with {algo_instance.name}")
            
            # Calculate hash
            hash_value = algo_instance.hash_string(text, encoding)
            
            self.logger.info(f"String hashing completed: {hash_value}")
            
            return hash_value
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"String hashing failed: {e}")
    
    def _save_hash_to_file(self, 
                          hash_value: str, 
                          algorithm: str, 
                          source_path: Path, 
                          hash_file_path: Path) -> None:
        """
        Save hash value to a file with metadata.
        
        Args:
            hash_value: The calculated hash value
            algorithm: Algorithm used for hashing
            source_path: Path to the original file/directory
            hash_file_path: Path where to save the hash file
        """
        try:
            content = f"""CryptoKit Hash File
===================

Source: {source_path}
Algorithm: {algorithm}
Hash: {hash_value}

Generated by CryptoKit (CK) - Cryptography Toolkit
"""
            
            with open(hash_file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"Hash saved to: {hash_file_path}")
            
        except IOError as e:
            self.logger.warning(f"Failed to save hash file: {e}")
            # Don't raise error, as the hash calculation was successful
    
    def get_available_algorithms(self) -> list:
        """
        Get list of available hash algorithms.
        
        Returns:
            List of algorithm names
        """
        return list_hash_algorithms()
    
    def verify_hash_file(self, hash_file_path: Union[str, Path]) -> dict:
        """
        Verify a hash file and return its metadata.
        
        Args:
            hash_file_path: Path to the hash file
            
        Returns:
            Dictionary with hash file metadata
            
        Raises:
            CKError: If hash file is invalid or cannot be read
        """
        try:
            hash_file_path = Path(hash_file_path)
            
            if not hash_file_path.exists():
                raise CKError(f"Hash file not found: {hash_file_path}")
            
            if not hash_file_path.is_file():
                raise CKError(f"Path is not a file: {hash_file_path}")
            
            with open(hash_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse hash file content
            lines = content.strip().split('\n')
            metadata = {}
            
            for line in lines:
                if line.startswith('Source:'):
                    metadata['source'] = line.split('Source:', 1)[1].strip()
                elif line.startswith('Algorithm:'):
                    metadata['algorithm'] = line.split('Algorithm:', 1)[1].strip()
                elif line.startswith('Hash:'):
                    metadata['hash'] = line.split('Hash:', 1)[1].strip()
            
            return metadata
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Hash file verification failed: {e}")
