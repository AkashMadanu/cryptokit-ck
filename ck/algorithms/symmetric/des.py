"""
Data Encryption Standard (DES) implementation for CryptoKit (CK)

Implements the DES symmetric encryption algorithm using the cryptography library.
DES is a legacy algorithm with 56-bit effective key size (64-bit with parity bits).
"""

import os
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

from ck.core.interfaces import CryptographicAlgorithm
from ck.core.exceptions import CKError


class DESAlgorithm(CryptographicAlgorithm):
    """
    DES (Data Encryption Standard) implementation.
    
    Uses CBC mode with PKCS7 padding for secure encryption.
    Key derivation is performed using PBKDF2 with SHA-256.
    """
    
    @property
    def name(self) -> str:
        """Get the algorithm name."""
        return "DES"
    
    @property
    def key_size(self) -> int:
        """Get the key size in bits (64-bit DES key)."""
        return 64
    
    def encrypt(self, data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Encrypt data using DES algorithm.
        
        Args:
            data: Plaintext data to encrypt
            key: 8-byte DES key
            **kwargs: Additional parameters (unused for DES)
            
        Returns:
            Encrypted data with IV prepended
            
        Raises:
            CKError: If encryption fails
        """
        try:
            # Validate key size
            if len(key) != 8:
                raise CKError(f"DES requires 8-byte key, got {len(key)} bytes")
            
            # Generate random IV
            iv = os.urandom(8)  # DES block size is 8 bytes
            
            # Create cipher
            cipher = Cipher(
                algorithms.DES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(64).padder()  # DES block size is 64 bits
            padded_data = padder.update(data)
            padded_data += padder.finalize()
            
            # Encrypt data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend IV to ciphertext
            return iv + ciphertext
            
        except Exception as e:
            raise CKError(f"DES encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Decrypt data using DES algorithm.
        
        Args:
            encrypted_data: Encrypted data with IV prepended
            key: 8-byte DES key
            **kwargs: Additional parameters (unused for DES)
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            CKError: If decryption fails
        """
        try:
            # Validate key size
            if len(key) != 8:
                raise CKError(f"DES requires 8-byte key, got {len(key)} bytes")
            
            # Validate minimum data size (IV + at least one block)
            if len(encrypted_data) < 16:  # 8 bytes IV + 8 bytes minimum data
                raise CKError("Encrypted data too short for DES")
            
            # Extract IV and ciphertext
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.DES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(64).unpadder()
            data = unpadder.update(padded_data)
            data += unpadder.finalize()
            
            return data
            
        except Exception as e:
            raise CKError(f"DES decryption failed: {str(e)}")
    
    def generate_key(self, password: str, salt: bytes, **kwargs) -> bytes:
        """
        Generate DES key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Random salt (at least 8 bytes recommended)
            **kwargs: Additional parameters:
                - iterations: Number of PBKDF2 iterations (default: 100000)
                
        Returns:
            8-byte DES key
            
        Raises:
            CKError: If key generation fails
        """
        try:
            iterations = kwargs.get('iterations', 100000)
            
            # Use PBKDF2 with SHA-256 to derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=8,  # DES key size
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode('utf-8'))
            return key
            
        except Exception as e:
            raise CKError(f"DES key generation failed: {str(e)}")
    
    def validate_key(self, key: bytes) -> bool:
        """
        Validate DES key.
        
        Args:
            key: Key to validate
            
        Returns:
            True if key is valid (8 bytes)
        """
        return len(key) == 8
    
    @staticmethod
    def generate_random_key() -> bytes:
        """
        Generate a random DES key.
        
        Returns:
            8-byte random DES key
        """
        return os.urandom(8)
    
    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """
        Convert key to hexadecimal string.
        
        Args:
            key: DES key bytes
            
        Returns:
            Hexadecimal string representation
        """
        return key.hex()
    
    @staticmethod
    def key_from_hex(hex_key: str) -> bytes:
        """
        Convert hexadecimal string to key bytes.
        
        Args:
            hex_key: Hexadecimal key string
            
        Returns:
            DES key bytes
            
        Raises:
            CKError: If hex string is invalid
        """
        try:
            key = bytes.fromhex(hex_key)
            if len(key) != 8:
                raise CKError(f"DES key must be 8 bytes, got {len(key)} bytes")
            return key
        except ValueError as e:
            raise CKError(f"Invalid hex key: {str(e)}")
