"""
CryptoKit (CK) - Cryptography Toolkit

A comprehensive, modular cryptography toolkit for educational and practical use.
"""

__version__ = "0.1.0-alpha"
__author__ = "CryptoKit Development Team"
__license__ = "MIT"

# Defer imports to avoid circular dependencies during development
try:
    from ck.core.config import ConfigManager
    from ck.core.logger import setup_logger
    
    # Initialize global configuration and logging
    config = ConfigManager()
    logger = setup_logger()
except ImportError:
    # During development, these may not be available yet
    config = None
    logger = None

__all__ = [
    "__version__",
    "__author__", 
    "__license__",
    "config",
    "logger"
]
