# CryptoKit (CK) - Cryptography Toolkit

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://linux.org)

**CryptoKit (CK)** is a comprehensive, modular cryptography toolkit designed to showcase cryptographic fundamentals through practical implementations. Built for Linux systems, it provides a unified CLI interface for encryption, hashing, hash analysis, steganography, and file metadata analysis.

## 🎯 Project Goals

This project demonstrates:
- **Symmetric Encryption**: Multiple algorithms with secure key management
- **Cryptographic Hashing**: File integrity and verification systems
- **Hash Analysis**: Automated detection and cracking integration
- **Steganography**: Data hiding in various file formats
- **File Analysis**: Comprehensive metadata extraction and security analysis

## 🏗️ Architecture

CryptoKit follows a modular, plugin-based architecture that emphasizes:
- **Flexibility**: Easy to add new algorithms and tools
- **Extensibility**: Plugin system for custom functionality
- **Maintainability**: Clean separation of concerns
- **Security**: Secure coding practices throughout

## 📁 Project Structure

```
CryptoKit/
├── ck/                     # Main package
│   ├── core/              # Core framework (config, logging, interfaces)
│   ├── encryption/        # Symmetric encryption module
│   ├── hashing/           # Hashing and verification
│   ├── cracking/          # Hash analysis and cracking
│   ├── steganography/     # Data hiding techniques
│   ├── metadata/          # File analysis and metadata
│   └── cli/               # Command-line interface
├── tests/                 # Comprehensive test suite
├── config/                # Configuration files
├── docs/                  # Documentation
└── scripts/               # Utility scripts
```

## 🚀 Features

### Phase 1: Symmetric Encryption ✅
- **Multiple Algorithms**: AES, ChaCha20, Blowfish, 3DES
- **Secure Key Derivation**: PBKDF2, Argon2 support
- **File & Directory Encryption**: Single files or entire directories
- **Integrity Protection**: HMAC verification included

### Phase 2: Hashing & Verification 🟡
- **Multiple Hash Algorithms**: SHA family, Blake2, MD5, CRC32
- **Batch Processing**: Efficient handling of multiple files
- **Integrity Verification**: Compare against known hash values
- **Merkle Tree Support**: Directory integrity verification

### Phase 3: Hash Analysis 🔴
- **Automatic Hash Detection**: Pattern-based identification
- **External Tool Integration**: John the Ripper, Hashcat
- **Time Estimation**: Cracking time predictions
- **Multiple Attack Modes**: Dictionary, brute force, hybrid

### Phase 4: Steganography 🔴
- **Image Steganography**: LSB, DCT-based techniques
- **Text Hiding**: Whitespace, Unicode methods
- **Binary Support**: Hide data in various file formats
- **Encryption Integration**: Encrypt before hiding

### Phase 5: File Analysis 🔴
- **Metadata Extraction**: Comprehensive file information
- **Content Analysis**: Entropy, pattern detection
- **Security Scanning**: Suspicious content identification
- **Multiple Output Formats**: JSON, CSV, human-readable

## 🛠️ Installation

### Prerequisites
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install python3-dev python3-pip libmagic1

# Install external tools (optional for hash cracking)
sudo apt install john hashcat

# For steganography (image processing)
sudo apt install libjpeg-dev libpng-dev
```

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/cryptokit.git
cd cryptokit

# Install Python dependencies
pip install -r requirements.txt

# Install CryptoKit
pip install -e .

# Verify installation
ck --version
```

## 📖 Quick Start

### Interactive Mode
```bash
# Start interactive menu
ck

# Or use specific commands
ck encrypt --file document.pdf --algorithm aes-256-gcm
ck hash --directory /path/to/files --algorithm sha256
ck crack --hash "5d41402abc4b2a76b9719d911017c592" --auto-detect
```

### Configuration
```bash
# View current configuration
ck config show

# Modify settings
ck config set encryption.default_algorithm aes-256-gcm
ck config set cracking.tools.hashcat.gpu_enabled true
```

## 🔧 Development

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v --cov=ck

# Code formatting
black ck/ tests/
flake8 ck/ tests/

# Type checking
mypy ck/
```

### Adding New Features
CryptoKit's modular architecture makes it easy to extend:

1. **New Encryption Algorithm**: Implement `CryptographicAlgorithm` interface
2. **New Hash Function**: Add to `hashing/algorithms.py`
3. **New Steganography Method**: Create plugin in `steganography/`
4. **New CLI Command**: Add to `cli/commands/`

## 📚 Documentation

- [API Documentation](docs/api/)
- [User Guide](docs/user-guide.md)
- [Developer Guide](docs/developer-guide.md)
- [Security Considerations](docs/security.md)

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/

# Generate coverage report
pytest --cov=ck --cov-report=html
```

## 🔒 Security Considerations

- **Memory Safety**: Secure deletion of sensitive data
- **Key Management**: Proper key derivation and storage
- **Randomness**: Cryptographically secure random number generation
- **Side-Channel Resistance**: Timing attack mitigation
- **Input Validation**: Comprehensive input sanitization

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎓 Educational Purpose

This project is designed for educational purposes to demonstrate:
- Cryptographic algorithm implementation
- Secure software development practices
- Modular architecture design
- CLI application development
- Integration with external security tools

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- [cryptography](https://github.com/pyca/cryptography) - Modern cryptographic library
- [John the Ripper](https://www.openwall.com/john/) - Password cracking tool
- [Hashcat](https://hashcat.net/hashcat/) - Advanced password recovery
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting

---

**Status**: 🚧 Active Development | **Version**: 0.1.0-alpha | **Python**: 3.9+
