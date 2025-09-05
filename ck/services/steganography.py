"""
Steganography service for CryptoKit.

This module provides high-level steganography operations including
data hiding, extraction, and capacity analysis.
"""

from pathlib import Path
from typing import Union, Optional, Tuple
import logging

from ck.algorithms.steganography import get_stego_algorithm, detect_file_type, list_stego_algorithms
from ck.core.exceptions import CKError


class SteganographyService:
    """
    High-level steganography service providing data hiding and extraction capabilities.
    """
    
    def __init__(self):
        """Initialize the steganography service."""
        self.logger = logging.getLogger('ck.steganography')
    
    def hide_data(self, 
                  cover_file: Union[str, Path],
                  secret_file: Union[str, Path],
                  output_file: Union[str, Path],
                  method: Optional[str] = None,
                  password: Optional[str] = None) -> bool:
        """
        Hide secret data from a file inside a cover file.
        
        Args:
            cover_file: Path to the cover file
            secret_file: Path to the file containing secret data
            output_file: Path for the output file with hidden data
            method: Steganography method (auto-detect if None)
            password: Optional password for encryption
            
        Returns:
            True if successful
            
        Raises:
            CKError: If hiding fails
        """
        try:
            cover_file = Path(cover_file)
            secret_file = Path(secret_file)
            output_file = Path(output_file)
            
            # Validate input files
            if not cover_file.exists():
                raise CKError(f"Cover file not found: {cover_file}")
            
            if not secret_file.exists():
                raise CKError(f"Secret file not found: {secret_file}")
            
            # Auto-detect method if not specified
            if method is None:
                method = detect_file_type(str(cover_file))
                self.logger.info(f"Auto-detected steganography method: {method}")
            
            # Get algorithm instance
            try:
                algo_class = get_stego_algorithm(method)
                algo_instance = algo_class()
            except ValueError as e:
                raise CKError(f"Invalid steganography method: {e}")
            
            self.logger.info(f"Using {algo_instance.name} to hide data in {cover_file}")
            
            # Validate cover file
            if not algo_instance.validate_cover_file(cover_file):
                raise CKError(f"Cover file {cover_file} is not compatible with {method} method")
            
            # Read secret data
            try:
                with open(secret_file, 'rb') as f:
                    secret_data = f.read()
            except IOError as e:
                raise CKError(f"Error reading secret file: {e}")
            
            # Check capacity
            capacity = algo_instance.calculate_capacity(cover_file)
            if len(secret_data) > capacity:
                raise CKError(f"Secret file too large. Maximum capacity: {capacity} bytes, "
                            f"secret file size: {len(secret_data)} bytes")
            
            # Hide the data
            success = algo_instance.hide_data(
                cover_file=cover_file,
                secret_data=secret_data,
                output_file=output_file,
                password=password
            )
            
            if success:
                self.logger.info(f"Successfully hidden {len(secret_data)} bytes in {output_file}")
                return True
            else:
                raise CKError("Steganography operation failed")
                
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Data hiding failed: {e}")
    
    def extract_data(self,
                     stego_file: Union[str, Path],
                     output_file: Optional[Union[str, Path]] = None,
                     method: Optional[str] = None,
                     password: Optional[str] = None) -> Union[bytes, Path]:
        """
        Extract hidden data from a steganography file.
        
        Args:
            stego_file: Path to the file containing hidden data
            output_file: Path to save extracted data (optional)
            method: Steganography method (auto-detect if None)
            password: Optional password for decryption
            
        Returns:
            Extracted data as bytes, or Path to output file if saved
            
        Raises:
            CKError: If extraction fails
        """
        try:
            stego_file = Path(stego_file)
            
            # Validate input file
            if not stego_file.exists():
                raise CKError(f"Steganography file not found: {stego_file}")
            
            # Auto-detect method if not specified
            if method is None:
                method = detect_file_type(str(stego_file))
                self.logger.info(f"Auto-detected steganography method: {method}")
            
            # Get algorithm instance
            try:
                algo_class = get_stego_algorithm(method)
                algo_instance = algo_class()
            except ValueError as e:
                raise CKError(f"Invalid steganography method: {e}")
            
            self.logger.info(f"Using {algo_instance.name} to extract data from {stego_file}")
            
            # Extract the data
            extracted_data = algo_instance.extract_data(
                stego_file=stego_file,
                password=password
            )
            
            self.logger.info(f"Successfully extracted {len(extracted_data)} bytes")
            
            # Save to file if output path specified
            if output_file:
                output_file = Path(output_file)
                try:
                    with open(output_file, 'wb') as f:
                        f.write(extracted_data)
                    self.logger.info(f"Extracted data saved to {output_file}")
                    return output_file
                except IOError as e:
                    raise CKError(f"Error saving extracted data: {e}")
            else:
                return extracted_data
                
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Data extraction failed: {e}")
    
    def analyze_capacity(self,
                        cover_file: Union[str, Path],
                        method: Optional[str] = None) -> dict:
        """
        Analyze the hiding capacity of a cover file.
        
        Args:
            cover_file: Path to the cover file
            method: Steganography method (auto-detect if None)
            
        Returns:
            Dictionary with capacity analysis
            
        Raises:
            CKError: If analysis fails
        """
        try:
            cover_file = Path(cover_file)
            
            if not cover_file.exists():
                raise CKError(f"Cover file not found: {cover_file}")
            
            # Auto-detect method if not specified
            if method is None:
                method = detect_file_type(str(cover_file))
            
            # Get algorithm instance
            try:
                algo_class = get_stego_algorithm(method)
                algo_instance = algo_class()
            except ValueError as e:
                raise CKError(f"Invalid steganography method: {e}")
            
            # Validate cover file
            if not algo_instance.validate_cover_file(cover_file):
                raise CKError(f"Cover file {cover_file} is not compatible with {method} method")
            
            # Calculate capacity
            capacity_bytes = algo_instance.calculate_capacity(cover_file)
            file_size = algo_instance.get_file_size(cover_file)
            
            return {
                'file': str(cover_file),
                'method': method,
                'algorithm': algo_instance.name,
                'file_size_bytes': file_size,
                'capacity_bytes': capacity_bytes,
                'capacity_kb': round(capacity_bytes / 1024, 2),
                'capacity_percentage': round((capacity_bytes / file_size) * 100, 2) if file_size > 0 else 0,
                'supported_formats': algo_instance.supported_formats
            }
            
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Capacity analysis failed: {e}")
    
    def get_available_methods(self) -> list:
        """
        Get list of available steganography methods.
        
        Returns:
            List of method names
        """
        return list_stego_algorithms()
    
    def hide_text_message(self,
                         cover_file: Union[str, Path],
                         message: str,
                         output_file: Union[str, Path],
                         method: Optional[str] = None,
                         password: Optional[str] = None) -> bool:
        """
        Hide a text message inside a cover file.
        
        Args:
            cover_file: Path to the cover file
            message: Text message to hide
            output_file: Path for the output file
            method: Steganography method (auto-detect if None)
            password: Optional password for encryption
            
        Returns:
            True if successful
        """
        try:
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            cover_file = Path(cover_file)
            output_file = Path(output_file)
            
            # Auto-detect method if not specified
            if method is None:
                method = detect_file_type(str(cover_file))
            
            # Get algorithm instance
            algo_class = get_stego_algorithm(method)
            algo_instance = algo_class()
            
            # Hide the message
            success = algo_instance.hide_data(
                cover_file=cover_file,
                secret_data=message_bytes,
                output_file=output_file,
                password=password
            )
            
            if success:
                self.logger.info(f"Successfully hidden text message ({len(message)} characters) in {output_file}")
                return True
            else:
                raise CKError("Text message hiding failed")
                
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Text message hiding failed: {e}")
    
    def extract_text_message(self,
                           stego_file: Union[str, Path],
                           method: Optional[str] = None,
                           password: Optional[str] = None) -> str:
        """
        Extract a hidden text message from a steganography file.
        
        Args:
            stego_file: Path to the file containing hidden message
            method: Steganography method (auto-detect if None)
            password: Optional password for decryption
            
        Returns:
            Extracted text message
        """
        try:
            # Extract data as bytes
            extracted_bytes = self.extract_data(
                stego_file=stego_file,
                method=method,
                password=password
            )
            
            # Convert bytes to text
            if isinstance(extracted_bytes, bytes):
                message = extracted_bytes.decode('utf-8')
                self.logger.info(f"Successfully extracted text message ({len(message)} characters)")
                return message
            else:
                raise CKError("Extracted data is not in expected format")
                
        except UnicodeDecodeError:
            raise CKError("Extracted data is not valid UTF-8 text")
        except Exception as e:
            if isinstance(e, CKError):
                raise
            raise CKError(f"Text message extraction failed: {e}")
