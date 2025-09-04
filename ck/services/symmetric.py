"""
Symmetric encryption service for CryptoKit (CK)

Provides high-level interface for symmetric encryption and decryption operations.
Handles file I/O, key management, and algorithm selection.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime

from ck.core.exceptions import CKError
from ck.core.logger import get_logger
from ck.algorithms.symmetric import get_algorithm, list_algorithms


class SymmetricEncryptionService:
    """
    Service for symmetric encryption and decryption operations.
    
    Handles file encryption/decryption, key generation and storage,
    and algorithm management.
    """
    
    def __init__(self):
        """Initialize the symmetric encryption service."""
        self.logger = get_logger(self.__class__.__name__)
        self._algorithms_cache = {}
    
    def get_available_algorithms(self) -> list:
        """
        Get list of available symmetric algorithms.
        
        Returns:
            List of algorithm names
        """
        return list_algorithms()
    
    def encrypt_file(
        self,
        input_file: Path,
        algorithm: str,
        password: Optional[str] = None,
        key_file: Optional[Path] = None,
        output_file: Optional[Path] = None
    ) -> Tuple[Path, Path]:
        """
        Encrypt a file using the specified algorithm.
        
        Args:
            input_file: Path to file to encrypt
            algorithm: Algorithm name (des, 3des, aes-128)
            password: Password for key derivation (if key_file not provided)
            key_file: Path to existing key file
            output_file: Path for encrypted output (default: input_file.txt)
            
        Returns:
            Tuple of (encrypted_file_path, key_file_path)
            
        Raises:
            CKError: If encryption fails
        """
        try:
            # Validate input file
            if not input_file.exists():
                raise CKError(f"Input file not found: {input_file}")
            
            # Set default output file
            if output_file is None:
                output_file = input_file.with_suffix(input_file.suffix + '.txt')
            
            # Get algorithm instance
            algo_class = get_algorithm(algorithm)
            algo_instance = algo_class()
            
            self.logger.info(f"Encrypting {input_file} with {algo_instance.name}")
            
            # Handle key
            if key_file and key_file.exists():
                # Load existing key
                key = self._load_key_from_file(key_file)
                key_file_path = key_file
            else:
                # Generate new key
                if not password:
                    raise CKError("Password required for key generation")
                
                key, key_file_path = self._generate_and_save_key(
                    algorithm=algorithm,
                    password=password,
                    input_file=input_file
                )
            
            # Read input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                raise CKError("Input file is empty")
            
            # Encrypt data
            encrypted_data = algo_instance.encrypt(data, key)
            
            # Write encrypted file
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info(f"File encrypted successfully: {output_file}")
            self.logger.info(f"Key saved to: {key_file_path}")
            
            return output_file, key_file_path
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Encryption failed: {str(e)}")
    
    def decrypt_file(
        self,
        encrypted_file: Path,
        key_file: Path,
        output_file: Optional[Path] = None
    ) -> Path:
        """
        Decrypt a file using the provided key.
        
        Args:
            encrypted_file: Path to encrypted file (.txt)
            key_file: Path to key file
            output_file: Path for decrypted output (default: remove .txt extension)
            
        Returns:
            Path to decrypted file
            
        Raises:
            CKError: If decryption fails
        """
        try:
            # Validate files
            if not encrypted_file.exists():
                raise CKError(f"Encrypted file not found: {encrypted_file}")
            
            if not key_file.exists():
                raise CKError(f"Key file not found: {key_file}")
            
            # Set default output file
            if output_file is None:
                if encrypted_file.suffix == '.txt':
                    output_file = encrypted_file.with_suffix('')
                else:
                    output_file = encrypted_file.with_suffix('.decrypted')
            
            # Load key and metadata
            key, metadata = self._load_key_from_file(key_file, include_metadata=True)
            algorithm = metadata.get('algorithm')
            
            if not algorithm:
                raise CKError("Key file missing algorithm information")
            
            # Get algorithm instance
            algo_class = get_algorithm(algorithm)
            algo_instance = algo_class()
            
            self.logger.info(f"Decrypting {encrypted_file} with {algo_instance.name}")
            
            # Read encrypted file
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            if len(encrypted_data) == 0:
                raise CKError("Encrypted file is empty")
            
            # Decrypt data
            decrypted_data = algo_instance.decrypt(encrypted_data, key)
            
            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"File decrypted successfully: {output_file}")
            
            return output_file
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Decryption failed: {str(e)}")
    
    def _generate_and_save_key(
        self,
        algorithm: str,
        password: str,
        input_file: Path
    ) -> Tuple[bytes, Path]:
        """
        Generate a new key and save it to file.
        
        Args:
            algorithm: Algorithm name
            password: Password for key derivation
            input_file: Input file (used for key filename)
            
        Returns:
            Tuple of (key_bytes, key_file_path)
        """
        # Get algorithm instance
        algo_class = get_algorithm(algorithm)
        algo_instance = algo_class()
        
        # Generate salt
        salt = os.urandom(16)
        
        # Generate key
        key = algo_instance.generate_key(password, salt)
        
        # Create key file path
        key_filename = f"Key_{input_file.stem}.txt"
        key_file_path = input_file.parent / key_filename
        
        # Prepare key data
        key_data = {
            'algorithm': algorithm,
            'key': key.hex(),
            'salt': salt.hex(),
            'created': datetime.now().isoformat(),
            'source_file': input_file.name
        }
        
        # Save key file
        with open(key_file_path, 'w') as f:
            f.write(f"# CryptoKit (CK) Key File\n")
            f.write(f"# Algorithm: {key_data['algorithm']}\n")
            f.write(f"# Created: {key_data['created']}\n")
            f.write(f"# Source File: {key_data['source_file']}\n")
            f.write(f"#\n")
            f.write(f"ALGORITHM={key_data['algorithm']}\n")
            f.write(f"KEY={key_data['key']}\n")
            f.write(f"SALT={key_data['salt']}\n")
            f.write(f"CREATED={key_data['created']}\n")
            f.write(f"SOURCE_FILE={key_data['source_file']}\n")
        
        return key, key_file_path
    
    def _load_key_from_file(
        self,
        key_file: Path,
        include_metadata: bool = False
    ) -> any:
        """
        Load key from file.
        
        Args:
            key_file: Path to key file
            include_metadata: Whether to return metadata
            
        Returns:
            Key bytes or tuple of (key_bytes, metadata)
        """
        try:
            metadata = {}
            key_hex = None
            
            with open(key_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line:
                        key_name, value = line.split('=', 1)
                        if key_name == 'KEY':
                            key_hex = value
                        else:
                            metadata[key_name.lower()] = value
            
            if not key_hex:
                raise CKError("No key found in key file")
            
            # Convert hex to bytes
            key = bytes.fromhex(key_hex)
            
            if include_metadata:
                return key, metadata
            else:
                return key
                
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Failed to load key file: {str(e)}")
    
    def generate_random_key(self, algorithm: str, output_file: Path) -> Path:
        """
        Generate a random key for the specified algorithm.
        
        Args:
            algorithm: Algorithm name
            output_file: Path for key file
            
        Returns:
            Path to generated key file
        """
        try:
            # Get algorithm instance
            algo_class = get_algorithm(algorithm)
            algo_instance = algo_class()
            
            # Generate random key
            if hasattr(algo_instance, 'generate_random_key'):
                key = algo_instance.generate_random_key()
            else:
                # Fallback: generate key from random password
                import secrets
                import string
                password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
                salt = os.urandom(16)
                key = algo_instance.generate_key(password, salt)
            
            # Prepare key data
            key_data = {
                'algorithm': algorithm,
                'key': key.hex(),
                'created': datetime.now().isoformat(),
                'type': 'random'
            }
            
            # Save key file
            with open(output_file, 'w') as f:
                f.write(f"# CryptoKit (CK) Key File\n")
                f.write(f"# Algorithm: {key_data['algorithm']}\n")
                f.write(f"# Created: {key_data['created']}\n")
                f.write(f"# Type: Random Key\n")
                f.write(f"#\n")
                f.write(f"ALGORITHM={key_data['algorithm']}\n")
                f.write(f"KEY={key_data['key']}\n")
                f.write(f"CREATED={key_data['created']}\n")
                f.write(f"TYPE={key_data['type']}\n")
            
            self.logger.info(f"Random key generated: {output_file}")
            return output_file
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Key generation failed: {str(e)}")
