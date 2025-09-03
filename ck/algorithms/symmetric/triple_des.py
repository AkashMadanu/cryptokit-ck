"""
Triple Data Encryption Standard (3DES) implementation for CryptoKit (CK)

Implements the 3DES symmetric encryption algorithm using the cryptography library.
3DES uses three iterations of DES with 168-bit effective key size (192-bit with parity bits).
"""

import os
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

from ck.core.interfaces import CryptographicAlgorithm
from ck.core.exceptions import CKError


class TripleDESAlgorithm(CryptographicAlgorithm):
    """
    3DES (Triple Data Encryption Standard) implementation.
    
    Uses CBC mode with PKCS7 padding for secure encryption.
    Key derivation is performed using PBKDF2 with SHA-256.
    Supports both 2-key (112-bit) and 3-key (168-bit) variants.
    """
    
    @property
    def name(self) -> str:
        """Get the algorithm name."""
        return "3DES"
    
    @property
    def key_size(self) -> int:
        """Get the key size in bits (192-bit for 3-key 3DES)."""
        return 192
    
    def encrypt(self, data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Encrypt data using 3DES algorithm.
        
        Args:
            data: Plaintext data to encrypt
            key: 24-byte 3DES key (or 16-byte for 2-key variant)
            **kwargs: Additional parameters (unused for 3DES)
            
        Returns:
            Encrypted data with IV prepended
            
        Raises:
            CKError: If encryption fails
        """
        try:
            # Validate and adjust key size
            key = self._prepare_key(key)
            
            # Generate random IV
            iv = os.urandom(8)  # 3DES block size is 8 bytes
            
            # Create cipher
            cipher = Cipher(
                algorithms.TripleDES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(64).padder()  # 3DES block size is 64 bits
            padded_data = padder.update(data)
            padded_data += padder.finalize()
            
            # Encrypt data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend IV to ciphertext
            return iv + ciphertext
            
        except Exception as e:
            raise CKError(f"3DES encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: bytes, key: bytes, **kwargs) -> bytes:
        """
        Decrypt data using 3DES algorithm.
        
        Args:
            encrypted_data: Encrypted data with IV prepended
            key: 24-byte 3DES key (or 16-byte for 2-key variant)
            **kwargs: Additional parameters (unused for 3DES)
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            CKError: If decryption fails
        """
        try:
            # Validate and adjust key size
            key = self._prepare_key(key)
            
            # Validate minimum data size (IV + at least one block)
            if len(encrypted_data) < 16:  # 8 bytes IV + 8 bytes minimum data
                raise CKError("Encrypted data too short for 3DES")
            
            # Extract IV and ciphertext
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.TripleDES(key),
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
            raise CKError(f"3DES decryption failed: {str(e)}")
    
    def generate_key(self, password: str, salt: bytes, **kwargs) -> bytes:
        """
        Generate 3DES key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Random salt (at least 8 bytes recommended)
            **kwargs: Additional parameters:
                - iterations: Number of PBKDF2 iterations (default: 100000)
                - key_variant: '2key' for 16-byte key, '3key' for 24-byte key (default)
                
        Returns:
            24-byte 3DES key (or 16-byte for 2-key variant)
            
        Raises:
            CKError: If key generation fails
        """
        try:
            iterations = kwargs.get('iterations', 100000)
            key_variant = kwargs.get('key_variant', '3key')
            
            # Determine key length based on variant
            if key_variant == '2key':
                key_length = 16  # 2-key 3DES
            else:
                key_length = 24  # 3-key 3DES (default)
            
            # Use PBKDF2 with SHA-256 to derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode('utf-8'))
            return key
            
        except Exception as e:
            raise CKError(f"3DES key generation failed: {str(e)}")
    
    def validate_key(self, key: bytes) -> bool:
        """
        Validate 3DES key.
        
        Args:
            key: Key to validate
            
        Returns:
            True if key is valid (16 or 24 bytes)
        """
        return len(key) in [16, 24]
    
    def _prepare_key(self, key: bytes) -> bytes:
        """
        Prepare and validate 3DES key.
        
        Args:
            key: Raw key bytes
            
        Returns:
            Properly formatted 3DES key
            
        Raises:
            CKError: If key is invalid
        """
        if len(key) == 16:
            # 2-key 3DES: K1, K2, K1 (duplicate first key as third)
            return key + key[:8]
        elif len(key) == 24:
            # 3-key 3DES: K1, K2, K3
            return key
        else:
            raise CKError(f"3DES requires 16 or 24-byte key, got {len(key)} bytes")
    
    @staticmethod
    def generate_random_key(variant: str = '3key') -> bytes:
        """
        Generate a random 3DES key.
        
        Args:
            variant: '2key' for 16-byte key, '3key' for 24-byte key
            
        Returns:
            Random 3DES key
        """
        if variant == '2key':
            return os.urandom(16)
        else:
            return os.urandom(24)
    
    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """
        Convert key to hexadecimal string.
        
        Args:
            key: 3DES key bytes
            
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
            3DES key bytes
            
        Raises:
            CKError: If hex string is invalid
        """
        try:
            key = bytes.fromhex(hex_key)
            if len(key) not in [16, 24]:
                raise CKError(f"3DES key must be 16 or 24 bytes, got {len(key)} bytes")
            return key
        except ValueError as e:
            raise CKError(f"Invalid hex key: {str(e)}")
