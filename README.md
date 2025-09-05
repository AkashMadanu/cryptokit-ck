# CryptoKit (CK)

A comprehensive cryptography toolkit for encryption, hashing, steganography, and file security analysis.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Examples](#examples)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Symmetric Encryption**: AES-128, 3DES encryption with secure key derivation
- **Cryptographic Hashing**: MD5, SHA1, SHA256, SHA512, BLAKE2 support
- **Hash Analysis**: Built-in dictionary-based hash cracking and analysis
- **Steganography**: Hide and extract data in images using LSB techniques
- **File Metadata Analysis**: Security scanning and threat detection
- **Interactive CLI**: User-friendly command-line interface
- **Multiple Output Formats**: JSON, CSV, detailed reports

## Installation

### Prerequisites

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install python3 python3-pip git
# or for newer versions:
sudo dnf install python3 python3-pip git
```

### Install CryptoKit

1. **Clone the repository:**
```bash
git clone https://github.com/AkashMadanu/cryptokit-ck.git
cd cryptokit-ck
```

2. **Create virtual environment (recommended):**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install using automated script:**
```bash
python3 install.py
```

**Or install manually:**
```bash
pip install -r requirements.txt
pip install -e .
```

4. **Verify installation:**
```bash
ck --version
ck --help
```

## Quick Start

```bash
# Start interactive mode
ck interactive

# Encrypt a file
ck encrypt document.txt --algorithm aes-128

# Generate file hash
ck hash file.txt --algorithm sha256

# Analyze file metadata
ck metadata suspicious_file.exe --format detailed

# Hide data in image
ck hide cover.jpg secret.txt output.jpg
```

## Commands

### Global Options

```bash
ck [COMMAND] [OPTIONS]

Global Options:
  --version                 Show version information
  --config FILE            Use custom configuration file
  --log-level LEVEL        Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  --quiet                  Suppress console output
  -h, --help               Show help message
```

### Available Commands

- [`encrypt`](#encrypt) - Encrypt files using symmetric algorithms
- [`decrypt`](#decrypt) - Decrypt files using symmetric algorithms  
- [`hash`](#hash) - Generate hashes of files or directories
- [`crack`](#crack) - Crack and analyze hashes
- [`hide`](#hide) - Hide data in files using steganography
- [`extract`](#extract) - Extract hidden data from files
- [`metadata`](#metadata) - Analyze file metadata and security
- [`config`](#config) - Manage configuration settings
- [`interactive`](#interactive) - Start interactive mode

## Examples

### Encrypt

Encrypt files using symmetric encryption algorithms.

```bash
# Basic encryption with password prompt
ck encrypt document.pdf --algorithm aes-128

# Encrypt with specified password (not recommended for production)
ck encrypt file.txt --algorithm 3des --password mypassword

# Encrypt with custom output file
ck encrypt data.txt --algorithm aes-128 --output encrypted_data.txt

# Use existing key file
ck encrypt file.txt --algorithm aes-128 --key-file existing_key.txt
```

**Options:**
- `--algorithm, -a`: Encryption algorithm (`aes-128`, `3des`)
- `--password, -p`: Encryption password (will prompt if not provided)
- `--output, -o`: Output file path (default: `input_file.txt`)
- `--key-file, -k`: Use existing key file

**Example Output:**
```
$ ck encrypt document.pdf --algorithm aes-128
Enter encryption password: [hidden]
Confirm password: [hidden]
Encrypting document.pdf with AES-128...
Encryption successful!
  Encrypted file: document.pdf.txt
  Key file: Key_document.pdf
```

### Decrypt

Decrypt files encrypted with CryptoKit.

```bash
# Basic decryption
ck decrypt encrypted_file.txt --key-file Key_original_file

# Decrypt with custom output
ck decrypt data.txt --key-file Key_data --output decrypted_data.pdf

# Decrypt multiple files (bash expansion)
for file in *.txt; do
    ck decrypt "$file" --key-file "Key_${file%.txt}"
done
```

**Options:**
- `--key-file, -k`: Key file for decryption (required)
- `--output, -o`: Output file path (default: remove `.txt` extension)

**Example Output:**
```
$ ck decrypt document.pdf.txt --key-file Key_document.pdf
Decrypting document.pdf.txt...
Decryption successful!
  Decrypted file: document.pdf
```

### Hash

Generate cryptographic hashes for files and directories.

```bash
# Hash single file
ck hash document.pdf --algorithm sha256

# Hash with different algorithms
ck hash file.txt --algorithm md5
ck hash file.txt --algorithm sha1
ck hash file.txt --algorithm blake2b

# Hash directory (all files)
ck hash /path/to/directory --algorithm sha256

# Hash without saving to file
ck hash file.txt --algorithm sha256 --no-save

# Hash with all supported algorithms
for algo in md5 sha1 sha256 sha384 sha512 blake2b blake2s; do
    ck hash file.txt --algorithm $algo
done
```

**Options:**
- `--algorithm, -a`: Hash algorithm (default: `sha256`)
  - Available: `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `blake2b`, `blake2s`
- `--no-save`: Don't save hash to file (print only)

**Example Output:**
```
$ ck hash document.pdf --algorithm sha256
Hashing file document.pdf with SHA256...
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Hash saved to: document.pdfHash.txt
```

### Crack

Analyze and attempt to crack cryptographic hashes.

```bash
# Detect hash type
ck crack 5d41402abc4b2a76b9719d911017c592 --detect

# Full analysis
ck crack 5d41402abc4b2a76b9719d911017c592 --analyze

# Quick crack attempt (common passwords)
ck crack 5d41402abc4b2a76b9719d911017c592 --quick

# Crack with custom wordlist
ck crack hash_value --wordlist /usr/share/wordlists/rockyou.txt

# Crack with specified hash type
ck crack hash_value --type md5 --max-length 8

# Brute force with custom length
ck crack hash_value --max-length 6
```

**Options:**
- `--type, -t`: Hash type (auto-detect if not specified)
- `--wordlist, -w`: Custom wordlist file
- `--max-length, -L`: Maximum brute force length (default: 6)
- `--quick`: Quick mode (top common passwords only)
- `--detect`: Detect hash type only
- `--analyze`: Full analysis (detection + strength assessment)

**Example Output:**
```
$ ck crack 5d41402abc4b2a76b9719d911017c592 --analyze

Performing comprehensive analysis of: 5d41402abc4b2a76b9719d911017c592

Detection
Type: MD5 (128 bits)
Description: MD5 message-digest algorithm
Confidence: 100.0%

Security
Algorithm Rating: Weak
Overall Rating: Poor (2/10)
Crack Difficulty: Very Easy
Estimated Time: Seconds to minutes

Vulnerabilities:
  - Cryptographically broken since 2004
  - Vulnerable to collision attacks
  - Fast computation enables brute force

Recommendations:
  Use SHA-256 or stronger algorithms for new applications
```

### Hide

Hide data in files using steganography techniques.

```bash
# Hide text in image
ck hide cover.jpg secret.txt output.jpg

# Hide with password protection
ck hide image.png data.txt stego.png --password mypassword

# Hide with specific method
ck hide cover.bmp secret.txt output.bmp --method lsb

# Hide text in text file
ck hide cover.txt secret.txt output.txt --method text

# Check capacity before hiding
ck hide large_image.png large_file.txt output.png
```

**Options:**
- `--password, -p`: Password for encryption
- `--method, -m`: Steganography method (`lsb`, `text`, `binary`) (default: `lsb`)

**Example Output:**
```
$ ck hide cover.jpg secret.txt output.jpg --password mykey
Analyzing cover file capacity...
Cover file: cover.jpg
Method: LSB Image Steganography
Capacity: 196608 bytes (192 KB)
File usage: 1.2%
Secret file size: 2341 bytes
Hiding secret.txt in cover.jpg...
Data hiding successful!
  Output file: output.jpg
  Hidden data: 2341 bytes
  Encryption: Yes (password protected)
```

### Extract

Extract hidden data from steganography files.

```bash
# Extract data from image
ck extract stego_image.jpg

# Extract with password
ck extract hidden.png --password mypassword

# Extract to specific file
ck extract stego.jpg --output extracted_data.txt

# Extract with specific method
ck extract file.txt --method text --output data.txt

# Auto-detect method
ck extract unknown_stego.png --output data.bin
```

**Options:**
- `--output, -o`: Output file for extracted data
- `--password, -p`: Password for decryption
- `--method, -m`: Steganography method (auto-detect if not specified)

**Example Output:**
```
$ ck extract stego.jpg --password mykey --output secret.txt
Extracting hidden data from stego.jpg...
Data extraction successful!
  Extracted file: secret.txt
  Extracted data: 2341 bytes
  Decryption: Yes (password used)
```

### Metadata

Analyze file metadata, content, and security indicators.

```bash
# Basic file analysis
ck metadata file.exe

# Detailed analysis
ck metadata suspicious.exe --format detailed

# Directory analysis
ck metadata /downloads --recursive

# Security-focused scan
ck metadata /tmp --recursive --risk-only

# Export to different formats
ck metadata file.pdf --format json --output report.json
ck metadata folder/ --format csv --output analysis.csv

# Large-scale analysis
ck metadata /home/user --recursive --max-files 1000 --max-size 50

# Pattern-based filtering
ck metadata /var/log --pattern "*.log" --recursive
```

**Options:**
- `--recursive, -r`: Analyze directory recursively
- `--format`: Output format (`summary`, `detailed`, `json`, `csv`) (default: `summary`)
- `--output, -o`: Save results to file
- `--max-size`: Maximum file size in MB (default: 100)
- `--max-files`: Maximum files to analyze (default: 100)
- `--pattern`: File pattern for filtering (default: `*`)
- `--risk-only`: Show only files with security risks
- `--no-content`: Skip content analysis
- `--no-security`: Skip security scanning
- `--show-strings`: Include string analysis

**Example Output:**
```
$ ck metadata suspicious.exe --format detailed

File Analysis Report
===================
File: suspicious.exe
Size: 524,288 bytes
Type: PE32 executable
MIME: application/x-dosexec

Security Assessment
------------------
Risk Level: HIGH (85/100)
Threats Detected: 3

Findings:
- Packed executable detected
- Suspicious string patterns found
- No digital signature
- High entropy sections

Recommendations:
- Scan with updated antivirus
- Execute in isolated environment
- Verify file source and integrity
```

### Config

Manage CryptoKit configuration settings.

```bash
# Show all configuration
ck config show

# Get specific setting
ck config get encryption.default_algorithm
ck config get hashing.chunk_size

# Set configuration values
ck config set encryption.default_algorithm aes-128
ck config set hashing.default_algorithm sha256
ck config set cli.colored_output true

# Configuration examples
ck config set cracking.tools.hashcat.gpu_enabled false
ck config set metadata.max_file_size 200MB
ck config set steganography.encryption_before_hiding true
```

**Actions:**
- `show`: Display current configuration
- `get <key>`: Get specific configuration value
- `set <key> <value>`: Set configuration value

**Example Output:**
```
$ ck config get encryption.default_algorithm
encryption.default_algorithm: aes-256-gcm

$ ck config set encryption.default_algorithm aes-128
Set encryption.default_algorithm = aes-128
```

### Interactive

Start interactive mode for guided operation.

```bash
# Start interactive mode
ck interactive

# Alternative syntax
ck i
```

**Interactive Menu:**
```
CryptoKit (CK) - Interactive Mode
A comprehensive cryptography toolkit
Type 'help' for available commands or 'quit' to exit

CK> help

Available Commands:
Command    Description                              Status
encrypt    Encrypt files with symmetric algorithms Available
decrypt    Decrypt files with symmetric algorithms Available
hash       Generate file hashes                    Available
crack      Crack & analyze hashes                  Available
hide       Hide data in files                      Available
extract    Extract hidden data                     Available
metadata   File metadata analysis                  Available
config     Configuration management                Available
help       Show this help                          Available
quit       Exit the program                        Available

CK> encrypt
Enter file path to encrypt: document.txt
Select algorithm:
  1. aes-128
  2. 3des
Select algorithm (1-2): 1
Enter encryption password: [hidden]
Confirm password: [hidden]
Encrypting document.txt with aes-128...
Encryption successful!
  Encrypted file: document.txt.txt
  Key file: Key_document.txt
```

## Configuration

CryptoKit uses YAML configuration files located in the `config/` directory.

### Configuration File Locations

- **Default**: `config/default.yaml`
- **User**: `~/.ck/config.yaml` (created automatically)
- **Custom**: Specify with `--config` option

### Key Configuration Sections

```yaml
# Encryption settings
encryption:
  default_algorithm: "aes-128"
  key_derivation: "argon2"
  iterations: 100000

# Hashing settings  
hashing:
  default_algorithm: "sha256"
  chunk_size: 65536

# Cracking settings
cracking:
  tools:
    hashcat:
      gpu_enabled: true
    john:
      path: "/usr/bin/john"

# CLI settings
cli:
  interactive_mode: true
  colored_output: true
  progress_bars: true
```

## Development

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=ck --cov-report=html
```

### Code Style

```bash
# Install formatting tools
pip install black flake8

# Format code
black ck/ tests/

# Check style
flake8 ck/ tests/
```

## Troubleshooting

### Common Issues

**Import Error:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall in development mode
pip install -e .
```

**Permission Denied:**
```bash
# Make sure you have write permissions
chmod +w /path/to/file

# For system-wide installation (not recommended)
sudo pip install -e .
```

**Module Not Found:**
```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Reinstall requirements
pip install -r requirements.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [cryptography](https://github.com/pyca/cryptography) - Modern cryptographic library
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [Pillow](https://github.com/python-pillow/Pillow) - Image processing library

## Security Notice

This tool is designed for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.
