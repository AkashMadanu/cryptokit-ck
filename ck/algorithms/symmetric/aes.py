"""
Advanced Encryption Standard (AES-128) implementation for CryptoKit (CK)

Implements the AES-128 symmetric encryption algorithm using the cryptography library.
AES-128 uses 128-bit keys and provides strong security with good performance.
"""

import os
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

from ck.core.interfaces import CryptographicAlgorithm
from ck.core.exceptions import CKError


class AES128Algorithm(CryptographicAlgorithm):
    """
    AES-128 (Advanced Encryption Standard with 128-bit key) implementation.
    
    Uses CBC mode with PKCS7 padding for secure encryption.
    Key derivation is performed using PBKDF2 with SHA-256.
    """
    
    @property
    def name(self) -> str:
        """Get the algorithm name."""
        return "AES-128"
    
    @property
    def key_size(self) -> int:
        """Get the key size in bits (128-bit AES key)."""
        return 128
    
    def encrypt(self, data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Encrypt data using AES-128 algorithm.
        
        Args:
            data: Plaintext data to encrypt
            key: 16-byte AES-128 key
            **kwargs: Additional parameters (unused for AES-128)
            
        Returns:
            Encrypted data with IV prepended
            
        Raises:
            CKError: If encryption fails
        """
        try:
            # Validate key size
            if len(key) != 16:
                raise CKError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
            
            # Generate random IV
            iv = os.urandom(16)  # AES block size is 16 bytes
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
            padded_data = padder.update(data)
            padded_data += padder.finalize()
            
            # Encrypt data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend IV to ciphertext
            return iv + ciphertext
            
        except Exception as e:
            raise CKError(f"AES-128 encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Decrypt data using AES-128 algorithm.
        
        Args:
            encrypted_data: Encrypted data with IV prepended
            key: 16-byte AES-128 key
            **kwargs: Additional parameters (unused for AES-128)
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            CKError: If decryption fails
        """
        try:
            # Validate key size
            if len(key) != 16:
                raise CKError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
            
            # Validate minimum data size (IV + at least one block)
            if len(encrypted_data) < 32:  # 16 bytes IV + 16 bytes minimum data
                raise CKError("Encrypted data too short for AES-128")
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data)
            data += unpadder.finalize()
            
            return data
            
        except Exception as e:
            raise CKError(f"AES-128 decryption failed: {str(e)}")
    
    def generate_key(self, password: str, salt: bytes, **kwargs) -> bytes:
        """
        Generate AES-128 key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Random salt (at least 16 bytes recommended)
            **kwargs: Additional parameters:
                - iterations: Number of PBKDF2 iterations (default: 100000)
                
        Returns:
            16-byte AES-128 key
            
        Raises:
            CKError: If key generation fails
        """
        try:
            iterations = kwargs.get('iterations', 100000)
            
            # Use PBKDF2 with SHA-256 to derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=16,  # AES-128 key size
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode('utf-8'))
            return key
            
        except Exception as e:
            raise CKError(f"AES-128 key generation failed: {str(e)}")
    
    def validate_key(self, key: bytes) -> bool:
        """
        Validate AES-128 key.
        
        Args:
            key: Key to validate
            
        Returns:
            True if key is valid (16 bytes)
        """
        return len(key) == 16
    
    @staticmethod
    def generate_random_key() -> bytes:
        """
        Generate a random AES-128 key.
        
        Returns:
            16-byte random AES-128 key
        """
        return os.urandom(16)
    
    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """
        Convert key to hexadecimal string.
        
        Args:
            key: AES-128 key bytes
            
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
            AES-128 key bytes
            
        Raises:
            CKError: If hex string is invalid
        """
        try:
            key = bytes.fromhex(hex_key)
            if len(key) != 16:
                raise CKError(f"AES-128 key must be 16 bytes, got {len(key)} bytes")
            return key
        except ValueError as e:
            raise CKError(f"Invalid hex key: {str(e)}")
    
    @staticmethod
    def generate_salt() -> bytes:
        """
        Generate a random salt for key derivation.
        
        Returns:
            16-byte random salt
        """
        return os.urandom(16)
