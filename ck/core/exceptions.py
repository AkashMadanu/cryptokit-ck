"""
Custom exceptions for CryptoKit (CK)

Defines all custom exception classes used throughout the application.
"""


class CKException(Exception):
    """Base exception class for all CryptoKit errors."""
    
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ConfigurationError(CKException):
    """Raised when there's an error in configuration."""
    pass


class EncryptionError(CKException):
    """Raised when encryption/decryption operations fail."""
    pass


class HashingError(CKException):
    """Raised when hashing operations fail."""
    pass


class CrackingError(CKException):
    """Raised when hash cracking operations fail."""
    pass


class SteganographyError(CKException):
    """Raised when steganography operations fail."""
    pass


class MetadataError(CKException):
    """Raised when metadata extraction fails."""
    pass


class ToolNotFoundError(CKException):
    """Raised when required external tool is not found."""
    pass


class InvalidAlgorithmError(CKException):
    """Raised when an unsupported algorithm is specified."""
    pass


class InvalidFileError(CKException):
    """Raised when file operations encounter invalid files."""
    pass


class InvalidHashError(CKException):
    """Raised when hash format or value is invalid."""
    pass


class PermissionError(CKException):
    """Raised when insufficient permissions for operation."""
    pass


class ValidationError(CKException):
    """Raised when input validation fails."""
    pass


# Alias for backward compatibility
CKError = CKException
