# CryptoKit (CK) - Quick Start Guide

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AkashMadanu/cryptokit-ck.git
   cd cryptokit-ck
   ```

2. **Install (Automated):**
   ```bash
   python install.py
   ```

   **Or Manual Installation:**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

3. **Verify installation:**
   ```bash
   ck --help
   ```

## Available Commands

### Encryption/Decryption
```bash
# Encrypt a file
ck encrypt document.pdf --algorithm aes-128 --password mypassword

# Decrypt a file
ck decrypt document.pdf.txt --key-file Key_document.pdf
```

### Hashing
```bash
# Hash a single file
ck hash file.txt --algorithm sha256

# Hash all files in directory
ck hash /path/to/directory
```

### Hash Cracking
```bash
# Crack MD5 hash
ck crack 5d41402abc4b2a76b9719d911017c592 --detect

# Crack with analysis
ck crack hash_value --analyze

# Quick crack attempt
ck crack hash_value --quick
```

### Steganography
```bash
# Hide data in image
ck hide cover.jpg secret.txt output.jpg --password mykey

# Extract hidden data
ck extract stego.jpg --password mykey --output extracted.txt
```

### Metadata Analysis
```bash
# Analyze single file
ck metadata suspicious.exe --format detailed

# Scan directory for security risks
ck metadata /downloads --recursive --risk-only

# Export analysis to CSV
ck metadata file.pdf --format csv --output report.csv
```

### Interactive Mode
```bash
# Start interactive mode
ck interactive
```

### Configuration
```bash
# Show current configuration
ck config show

# Set configuration value
ck config set encryption.default_algorithm aes-128
```

## Common Use Cases

1. **File Security Analysis:**
   ```bash
   ck metadata suspicious_download.exe --format json --output analysis.json
   ```

2. **Data Protection:**
   ```bash
   ck encrypt sensitive_data.zip --algorithm aes-128
   ```

3. **Integrity Verification:**
   ```bash
   ck hash important_file.pdf --algorithm sha256
   ```

4. **Digital Forensics:**
   ```bash
   ck metadata /evidence --recursive --format csv --output investigation.csv
   ```

## Output Formats

- **summary** - Human-readable overview (default)
- **detailed** - Comprehensive analysis report
- **json** - Machine-readable structured data
- **csv** - Spreadsheet-compatible format

## Security Features

- AES-128/3DES encryption
- Secure key derivation (PBKDF2)
- File type detection
- Malware pattern scanning
- Vulnerability assessment
- Risk scoring and recommendations

Get started with CryptoKit today!
