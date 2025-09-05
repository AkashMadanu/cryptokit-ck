"""
LSB (Least Significant Bit) Image Steganography implementation.

This module implements LSB steganography for hiding data in image files
by modifying the least significant bits of pixel values.
"""

from pathlib import Path
from typing import Union, Optional
import struct
from PIL import Image
import io

from .base import SteganographyAlgorithm


class LSBImageSteganography(SteganographyAlgorithm):
    """
    LSB (Least Significant Bit) image steganography implementation.
    
    This algorithm hides data in the least significant bits of image pixels,
    making the changes virtually invisible to the human eye.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "LSB Image Steganography"
    
    @property
    def supported_formats(self) -> list:
        """Return list of supported image formats."""
        return ['.png', '.bmp', '.tiff', '.tif']
    
    def calculate_capacity(self, cover_file: Union[str, Path]) -> int:
        """
        Calculate the maximum number of bytes that can be hidden in the image.
        
        Uses 1 bit per color channel (R, G, B) for LSB hiding.
        Reserves some space for metadata (length header).
        
        Args:
            cover_file: Path to the cover image
            
        Returns:
            Maximum capacity in bytes
        """
        cover_file = Path(cover_file)
        
        if not self.validate_cover_file(cover_file):
            raise ValueError(f"Invalid cover file: {cover_file}")
        
        try:
            with Image.open(cover_file) as img:
                # Convert to RGB if not already
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                width, height = img.size
                total_pixels = width * height
                
                # 3 bits per pixel (R, G, B channels)
                # 8 bits = 1 byte, so total_pixels * 3 / 8 = bytes
                total_bits = total_pixels * 3
                total_bytes = total_bits // 8
                
                # Reserve 4 bytes for data length header
                usable_bytes = total_bytes - 4
                
                return max(0, usable_bytes)
                
        except Exception as e:
            raise IOError(f"Error reading image file: {e}")
    
    def hide_data(self, 
                  cover_file: Union[str, Path],
                  secret_data: bytes,
                  output_file: Union[str, Path],
                  password: Optional[str] = None) -> bool:
        """
        Hide secret data in the cover image using LSB technique.
        
        Args:
            cover_file: Path to the cover image
            secret_data: Data to hide
            output_file: Path for the output image
            password: Optional password for encryption
            
        Returns:
            True if successful
        """
        cover_file = Path(cover_file)
        output_file = Path(output_file)
        
        if not self.validate_cover_file(cover_file):
            raise ValueError(f"Invalid cover file: {cover_file}")
        
        # Prepare secret data (encrypt if password provided)
        prepared_data = self.prepare_secret_data(secret_data, password)
        
        # Check capacity
        capacity = self.calculate_capacity(cover_file)
        if len(prepared_data) > capacity:
            raise ValueError(f"Secret data too large. Maximum capacity: {capacity} bytes, "
                           f"data size: {len(prepared_data)} bytes")
        
        try:
            with Image.open(cover_file) as img:
                # Convert to RGB if needed
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Create a copy to modify
                stego_img = img.copy()
                pixels = list(stego_img.getdata())
                
                # Convert data to binary string with length header
                data_length = len(prepared_data)
                length_bytes = struct.pack('<I', data_length)  # 4-byte little-endian unsigned int
                full_data = length_bytes + prepared_data
                
                # Convert to binary string
                binary_data = ''.join(format(byte, '08b') for byte in full_data)
                
                # Hide data in LSBs
                data_index = 0
                modified_pixels = []
                
                for pixel in pixels:
                    r, g, b = pixel
                    
                    if data_index < len(binary_data):
                        # Modify red channel LSB
                        r = (r & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    
                    if data_index < len(binary_data):
                        # Modify green channel LSB  
                        g = (g & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    
                    if data_index < len(binary_data):
                        # Modify blue channel LSB
                        b = (b & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    
                    modified_pixels.append((r, g, b))
                    
                    # Stop if all data is embedded
                    if data_index >= len(binary_data):
                        # Add remaining unmodified pixels
                        modified_pixels.extend(pixels[len(modified_pixels):])
                        break
                
                # Create new image with modified pixels
                stego_img.putdata(modified_pixels)
                
                # Save the image
                stego_img.save(output_file, format='PNG')  # Always save as PNG to avoid compression
                
                return True
                
        except Exception as e:
            raise IOError(f"Error processing image: {e}")
    
    def extract_data(self,
                     stego_file: Union[str, Path],
                     password: Optional[str] = None) -> bytes:
        """
        Extract hidden data from a steganography image.
        
        Args:
            stego_file: Path to the image containing hidden data
            password: Optional password for decryption
            
        Returns:
            Extracted secret data
        """
        stego_file = Path(stego_file)
        
        if not stego_file.exists():
            raise FileNotFoundError(f"Stego file not found: {stego_file}")
        
        try:
            with Image.open(stego_file) as img:
                # Convert to RGB if needed
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                pixels = list(img.getdata())
                
                # Extract binary data from LSBs
                binary_data = ""
                
                # First, extract the length (4 bytes = 32 bits)
                for i in range(32):  # 32 bits for length
                    if i // 3 >= len(pixels):
                        raise ValueError("Image too small to contain valid data")
                    
                    pixel = pixels[i // 3]
                    channel = i % 3
                    
                    # Extract LSB from appropriate channel
                    if channel == 0:  # Red
                        bit = pixel[0] & 1
                    elif channel == 1:  # Green
                        bit = pixel[1] & 1
                    else:  # Blue
                        bit = pixel[2] & 1
                    
                    binary_data += str(bit)
                
                # Convert first 32 bits to data length
                length_bits = binary_data[:32]
                data_length = struct.unpack('<I', int(length_bits, 2).to_bytes(4, 'big'))[0]
                
                # Validate data length
                if data_length <= 0 or data_length > self.calculate_capacity(stego_file):
                    raise ValueError("Invalid data length found in image")
                
                # Extract the actual data
                binary_data = ""
                total_bits_needed = 32 + (data_length * 8)  # length header + data
                
                for i in range(total_bits_needed):
                    if i // 3 >= len(pixels):
                        raise ValueError("Unexpected end of image data")
                    
                    pixel = pixels[i // 3]
                    channel = i % 3
                    
                    # Extract LSB from appropriate channel
                    if channel == 0:  # Red
                        bit = pixel[0] & 1
                    elif channel == 1:  # Green
                        bit = pixel[1] & 1
                    else:  # Blue
                        bit = pixel[2] & 1
                    
                    binary_data += str(bit)
                
                # Convert binary to bytes (skip length header)
                data_bits = binary_data[32:]  # Skip first 32 bits (length)
                extracted_bytes = bytearray()
                
                for i in range(0, len(data_bits), 8):
                    if i + 8 <= len(data_bits):
                        byte_bits = data_bits[i:i+8]
                        extracted_bytes.append(int(byte_bits, 2))
                
                # Recover original secret data (decrypt if needed)
                return self.recover_secret_data(bytes(extracted_bytes), password)
                
        except Exception as e:
            raise IOError(f"Error extracting data from image: {e}")
