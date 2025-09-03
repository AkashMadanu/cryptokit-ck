"""
Symmetric encryption algorithms for CryptoKit (CK)

This module provides implementations of various symmetric encryption algorithms
including DES, 3DES, and AES-128.
"""

from .des import DESAlgorithm
from .triple_des import TripleDESAlgorithm
from .aes import AES128Algorithm

__all__ = [
    'DESAlgorithm',
    'TripleDESAlgorithm', 
    'AES128Algorithm'
]

# Algorithm registry for easy access
SYMMETRIC_ALGORITHMS = {
    '3des': TripleDESAlgorithm,
    'aes-128': AES128Algorithm,
    'aes': AES128Algorithm,  # Alias for AES-128
}

def get_algorithm(name: str):
    """
    Get algorithm class by name.
    
    Args:
        name: Algorithm name (case-insensitive)
        
    Returns:
        Algorithm class
        
    Raises:
        KeyError: If algorithm not found
    """
    name_lower = name.lower().replace('_', '-')
    if name_lower not in SYMMETRIC_ALGORITHMS:
        available = ', '.join(SYMMETRIC_ALGORITHMS.keys())
        raise KeyError(f"Unknown algorithm '{name}'. Available: {available}")
    
    return SYMMETRIC_ALGORITHMS[name_lower]

def list_algorithms():
    """
    Get list of available symmetric algorithms.
    
    Returns:
        List of algorithm names
    """
    return list(SYMMETRIC_ALGORITHMS.keys())
