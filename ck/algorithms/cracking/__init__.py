"""
Hash cracking algorithms for CryptoKit (CK)

Simple, built-in hash cracking capabilities including hash detection,
dictionary attacks, and strength analysis.
"""

from .detector import HashDetector
from .dictionary import DictionaryAttack
from .analyzer import HashAnalyzer

__all__ = [
    "HashDetector",
    "DictionaryAttack", 
    "HashAnalyzer"
]
