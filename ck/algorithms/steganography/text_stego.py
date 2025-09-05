"""
Text-based steganography implementation.

This module implements steganographic techniques for hiding data in text files
using whitespace manipulation and invisible characters.
"""

from pathlib import Path
from typing import Union, Optional
import struct

from .base import SteganographyAlgorithm


class TextSteganography(SteganographyAlgorithm):
    """
    Text steganography implementation using whitespace patterns.
    
    This algorithm hides data by using spaces and tabs at the end of lines
    to encode binary information.
    """
    
    @property
    def name(self) -> str:
        """Return the algorithm name."""
        return "Text Whitespace Steganography"
    
    @property
    def supported_formats(self) -> list:
        """Return list of supported text formats."""
        return ['.txt', '.md', '.py', '.js', '.html', '.xml', '.css', '.rtf']
    
    def calculate_capacity(self, cover_file: Union[str, Path]) -> int:
        """
        Calculate the maximum number of bytes that can be hidden in the text file.
        
        Uses 2 bits per line (space=0, tab=1 for two positions).
        
        Args:
            cover_file: Path to the cover text file
            
        Returns:
            Maximum capacity in bytes
        """
        cover_file = Path(cover_file)
        
        if not self.validate_cover_file(cover_file):
            raise ValueError(f"Invalid cover file: {cover_file}")
        
        try:
            with open(cover_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            line_count = len(lines)
            
            # 2 bits per line (we'll add 2 whitespace chars at end of each line)
            # 8 bits = 1 byte, so line_count * 2 / 8 = bytes
            total_bits = line_count * 2
            total_bytes = total_bits // 8
            
            # Reserve 4 bytes for data length header
            usable_bytes = total_bytes - 4
            
            return max(0, usable_bytes)
            
        except Exception as e:
            raise IOError(f"Error reading text file: {e}")
    
    def hide_data(self, 
                  cover_file: Union[str, Path],
                  secret_data: bytes,
                  output_file: Union[str, Path],
                  password: Optional[str] = None) -> bool:
        """
        Hide secret data in the text file using whitespace patterns.
        
        Args:
            cover_file: Path to the cover text file
            secret_data: Data to hide
            output_file: Path for the output text file
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
            # Read the original text
            with open(cover_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Convert data to binary string with length header
            data_length = len(prepared_data)
            length_bytes = struct.pack('<I', data_length)  # 4-byte little-endian unsigned int
            full_data = length_bytes + prepared_data
            
            # Convert to binary string
            binary_data = ''.join(format(byte, '08b') for byte in full_data)
            
            # Hide data in whitespace at end of lines
            data_index = 0
            modified_lines = []
            
            for line in lines:
                # Remove existing trailing whitespace
                line = line.rstrip()
                
                if data_index < len(binary_data):
                    # Encode 2 bits per line using space/tab combinations
                    # 00 = space+space, 01 = space+tab, 10 = tab+space, 11 = tab+tab
                    
                    bit1 = binary_data[data_index] if data_index < len(binary_data) else '0'
                    bit2 = binary_data[data_index + 1] if data_index + 1 < len(binary_data) else '0'
                    
                    if bit1 == '0' and bit2 == '0':
                        line += '  '  # space + space
                    elif bit1 == '0' and bit2 == '1':
                        line += ' \t'  # space + tab
                    elif bit1 == '1' and bit2 == '0':
                        line += '\t '  # tab + space
                    else:  # bit1 == '1' and bit2 == '1'
                        line += '\t\t'  # tab + tab
                    
                    data_index += 2
                
                # Add newline if it was originally there
                if not line.endswith('\n') and (line != lines[-1] or lines[-1].endswith('\n')):
                    line += '\n'
                
                modified_lines.append(line)
                
                # Stop if all data is embedded
                if data_index >= len(binary_data):
                    # Add remaining unmodified lines
                    for remaining_line in lines[len(modified_lines):]:
                        modified_lines.append(remaining_line.rstrip() + '\n' if remaining_line.endswith('\n') else remaining_line.rstrip())
                    break
            
            # Write the modified text
            with open(output_file, 'w', encoding='utf-8') as f:
                f.writelines(modified_lines)
            
            return True
            
        except Exception as e:
            raise IOError(f"Error processing text file: {e}")
    
    def extract_data(self,
                     stego_file: Union[str, Path],
                     password: Optional[str] = None) -> bytes:
        """
        Extract hidden data from a steganography text file.
        
        Args:
            stego_file: Path to the text file containing hidden data
            password: Optional password for decryption
            
        Returns:
            Extracted secret data
        """
        stego_file = Path(stego_file)
        
        if not stego_file.exists():
            raise FileNotFoundError(f"Stego file not found: {stego_file}")
        
        try:
            with open(stego_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Extract binary data from whitespace patterns
            binary_data = ""
            
            for line in lines:
                # Check if line has trailing whitespace
                if len(line) >= 2 and line[-1] in [' ', '\t', '\n']:
                    # Get the last 2 characters before newline
                    if line.endswith('\n'):
                        whitespace = line[-3:-1] if len(line) >= 3 else line[:-1]
                    else:
                        whitespace = line[-2:] if len(line) >= 2 else line
                    
                    # Decode whitespace pattern to bits
                    if len(whitespace) >= 2:
                        char1, char2 = whitespace[0], whitespace[1]
                        
                        if char1 == ' ' and char2 == ' ':
                            binary_data += '00'
                        elif char1 == ' ' and char2 == '\t':
                            binary_data += '01'
                        elif char1 == '\t' and char2 == ' ':
                            binary_data += '10'
                        elif char1 == '\t' and char2 == '\t':
                            binary_data += '11'
            
            # Check if we have enough data for length header
            if len(binary_data) < 32:
                raise ValueError("Not enough whitespace data found in file")
            
            # Extract data length from first 32 bits
            length_bits = binary_data[:32]
            data_length = struct.unpack('<I', int(length_bits, 2).to_bytes(4, 'big'))[0]
            
            # Validate data length
            if data_length <= 0 or data_length > self.calculate_capacity(stego_file):
                raise ValueError("Invalid data length found in file")
            
            # Extract the actual data
            total_bits_needed = 32 + (data_length * 8)  # length header + data
            
            if len(binary_data) < total_bits_needed:
                raise ValueError("Not enough data found in file")
            
            # Convert binary to bytes (skip length header)
            data_bits = binary_data[32:total_bits_needed]  # Skip first 32 bits (length)
            extracted_bytes = bytearray()
            
            for i in range(0, len(data_bits), 8):
                if i + 8 <= len(data_bits):
                    byte_bits = data_bits[i:i+8]
                    extracted_bytes.append(int(byte_bits, 2))
            
            # Recover original secret data (decrypt if needed)
            return self.recover_secret_data(bytes(extracted_bytes), password)
            
        except Exception as e:
            raise IOError(f"Error extracting data from text file: {e}")
