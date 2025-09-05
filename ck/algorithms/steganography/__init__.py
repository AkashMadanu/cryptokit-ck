"""
Steganography algorithms module for CryptoKit.

This module provides implementations of various steganographic techniques
for hiding data in images, text files, and other media.
"""

from .base import SteganographyAlgorithm
from .lsb_image import LSBImageSteganography
from .text_stego import TextSteganography

__all__ = [
    'SteganographyAlgorithm',
    'LSBImageSteganography', 
    'TextSteganography'
]

# Algorithm registry for easy access
STEGO_ALGORITHMS = {
    'lsb': LSBImageSteganography,
    'text': TextSteganography,
    # 'binary': BinarySteganography,  # Future implementation
}

def get_stego_algorithm(name: str) -> type:
    """
    Get steganography algorithm class by name.
    
    Args:
        name: Algorithm name (lsb, text, binary)
        
    Returns:
        Steganography algorithm class
        
    Raises:
        ValueError: If algorithm not found
    """
    name = name.lower()
    if name not in STEGO_ALGORITHMS:
        available = ', '.join(STEGO_ALGORITHMS.keys())
        raise ValueError(f"Steganography algorithm '{name}' not supported. Available: {available}")
    
    return STEGO_ALGORITHMS[name]

def list_stego_algorithms() -> list:
    """Get list of available steganography algorithm names."""
    return list(STEGO_ALGORITHMS.keys())

def detect_file_type(file_path: str) -> str:
    """
    Detect file type and suggest appropriate steganography method.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Suggested algorithm name
    """
    from pathlib import Path
    
    file_path = Path(file_path)
    ext = file_path.suffix.lower()
    
    # Image files - use LSB
    if ext in ['.png', '.bmp']:
        return 'lsb'
    elif ext in ['.jpg', '.jpeg']:
        return 'lsb'  # Will warn about JPEG limitations
    
    # Text files - use text steganography  
    elif ext in ['.txt', '.rtf', '.html', '.xml']:
        return 'text'
    
    # Default to LSB for unknown types
    else:
        return 'lsb'
