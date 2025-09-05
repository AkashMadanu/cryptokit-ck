# CryptoKit (CK) - Complete Command Reference

## Overview

CryptoKit is a comprehensive cryptography toolkit that provides encryption, hashing, steganography, and file analysis capabilities through a command-line interface.

## Global Usage

```
ck [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS] [ARGUMENTS]
```

### Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version information and exit |
| `--config FILE` | Use custom configuration file |
| `--log-level LEVEL` | Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `--quiet` | Suppress console output (log to file only) |
| `-h, --help` | Show help message |

## Commands

### 1. encrypt - File Encryption

**Purpose**: Encrypt files using symmetric encryption algorithms.

**Usage**:
```bash
ck encrypt FILE [OPTIONS]
```

**Arguments**:
- `FILE`: Path to file to encrypt

**Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--algorithm` | `-a` | Encryption algorithm (aes-128, 3des) | Prompt |
| `--password` | `-p` | Encryption password | Prompt |
| `--output` | `-o` | Output file path | `{input}.txt` |
| `--key-file` | `-k` | Use existing key file | Generate new |

**Examples**:
```bash
# Basic encryption with interactive prompts
ck encrypt document.pdf

# Specify algorithm
ck encrypt file.txt --algorithm aes-128

# Use custom output file
ck encrypt data.txt --algorithm 3des --output encrypted.txt

# Use existing key file
ck encrypt new_file.txt --key-file existing_key.txt
```

**Output Files**:
- Encrypted file: `{original_name}.txt`
- Key file: `Key_{original_name}`

---

### 2. decrypt - File Decryption

**Purpose**: Decrypt files encrypted with CryptoKit.

**Usage**:
```bash
ck decrypt FILE --key-file KEY_FILE [OPTIONS]
```

**Arguments**:
- `FILE`: Path to encrypted file (.txt)

**Required Options**:
| Option | Short | Description |
|--------|-------|-------------|
| `--key-file` | `-k` | Key file for decryption |

**Optional Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file path | Remove `.txt` extension |

**Examples**:
```bash
# Basic decryption
ck decrypt document.pdf.txt --key-file Key_document.pdf

# Custom output file
ck decrypt encrypted.txt --key-file Key_data --output original.pdf

# Batch decryption
for file in *.txt; do
    ck decrypt "$file" --key-file "Key_${file%.txt}"
done
```

---

### 3. hash - File Hashing

**Purpose**: Generate cryptographic hashes for files and directories.

**Usage**:
```bash
ck hash TARGET [OPTIONS]
```

**Arguments**:
- `TARGET`: File or directory path

**Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--algorithm` | `-a` | Hash algorithm | `sha256` |
| `--no-save` | | Don't save hash to file | Save to file |

**Supported Algorithms**:
- `md5` - MD5 (128-bit)
- `sha1` - SHA-1 (160-bit)
- `sha256` - SHA-256 (256-bit)
- `sha384` - SHA-384 (384-bit)
- `sha512` - SHA-512 (512-bit)
- `blake2b` - BLAKE2b (512-bit)
- `blake2s` - BLAKE2s (256-bit)

**Examples**:
```bash
# Hash single file
ck hash document.pdf --algorithm sha256

# Hash directory
ck hash /home/user/documents

# Multiple algorithms
ck hash file.txt --algorithm md5
ck hash file.txt --algorithm sha1
ck hash file.txt --algorithm sha256

# Don't save to file
ck hash file.txt --no-save
```

**Output**:
- Console: Algorithm name and hash value
- File: `{filename}Hash.txt` (if not using --no-save)

---

### 4. crack - Hash Analysis and Cracking

**Purpose**: Analyze hash types and attempt to crack passwords.

**Usage**:
```bash
ck crack HASH_VALUE [OPTIONS]
```

**Arguments**:
- `HASH_VALUE`: The hash to analyze/crack

**Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--type` | `-t` | Hash type | Auto-detect |
| `--wordlist` | `-w` | Custom wordlist file | Built-in list |
| `--max-length` | `-L` | Max brute force length | 6 |
| `--quick` | | Quick mode (common passwords) | Full mode |
| `--detect` | | Detection only | Crack attempt |
| `--analyze` | | Full analysis | Crack attempt |

**Hash Types Supported**:
- MD5, SHA-1, SHA-256, SHA-384, SHA-512
- BLAKE2b, BLAKE2s
- Auto-detection based on length and patterns

**Examples**:
```bash
# Auto-detect and crack
ck crack 5d41402abc4b2a76b9719d911017c592

# Detection only
ck crack 5d41402abc4b2a76b9719d911017c592 --detect

# Full analysis
ck crack hash_value --analyze

# Quick crack attempt
ck crack hash_value --quick

# Custom wordlist
ck crack hash_value --wordlist /usr/share/wordlists/rockyou.txt

# Brute force with length limit
ck crack hash_value --max-length 8
```

**Output Modes**:
1. **Detection**: Hash type, confidence, description
2. **Analysis**: Security assessment, vulnerabilities, recommendations
3. **Cracking**: Password if found, method used, time taken

---

### 5. hide - Steganography Hiding

**Purpose**: Hide data in cover files using steganography.

**Usage**:
```bash
ck hide COVER_FILE SECRET_FILE OUTPUT_FILE [OPTIONS]
```

**Arguments**:
- `COVER_FILE`: Cover file (image/text)
- `SECRET_FILE`: File containing secret data
- `OUTPUT_FILE`: Output file with hidden data

**Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--password` | `-p` | Encryption password | No encryption |
| `--method` | `-m` | Steganography method | `lsb` |

**Methods**:
- `lsb`: LSB (Least Significant Bit) for images
- `text`: Whitespace encoding for text files
- `binary`: Binary encoding

**Supported Formats**:
- **Images**: PNG, BMP, TIFF
- **Text**: Any text file

**Examples**:
```bash
# Hide in image
ck hide cover.jpg secret.txt output.jpg

# Hide with password
ck hide image.png data.txt stego.png --password mykey

# Hide in text file
ck hide document.txt secret.txt output.txt --method text

# Check capacity first
ck hide large_cover.png large_secret.txt output.png
```

**Capacity Analysis**:
The tool automatically analyzes cover file capacity and warns if the secret file is too large.

---

### 6. extract - Steganography Extraction

**Purpose**: Extract hidden data from steganography files.

**Usage**:
```bash
ck extract STEGO_FILE [OPTIONS]
```

**Arguments**:
- `STEGO_FILE`: File containing hidden data

**Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file for extracted data | Auto-generate |
| `--password` | `-p` | Decryption password | No decryption |
| `--method` | `-m` | Steganography method | Auto-detect |

**Examples**:
```bash
# Extract from image
ck extract stego_image.jpg

# Extract with password
ck extract hidden.png --password mykey

# Extract to specific file
ck extract stego.jpg --output secret.txt

# Specify method
ck extract text_stego.txt --method text --output data.txt
```

**Output**:
- Extracted data saved to file or displayed if small text
- Size and encryption status reported

---

### 7. metadata - File Analysis

**Purpose**: Analyze file metadata, content, and security indicators.

**Usage**:
```bash
ck metadata PATH [OPTIONS]
```

**Arguments**:
- `PATH`: File or directory path

**Options**:
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--recursive` | `-r` | Analyze directory recursively | Single level |
| `--format` | | Output format | `summary` |
| `--output` | `-o` | Save results to file | Console only |
| `--max-size` | | Maximum file size (MB) | 100 |
| `--max-files` | | Maximum files to analyze | 100 |
| `--pattern` | | File pattern filter | `*` |
| `--risk-only` | | Show only risky files | All files |
| `--no-content` | | Skip content analysis | Include content |
| `--no-security` | | Skip security scanning | Include security |
| `--show-strings` | | Include string analysis | Exclude strings |

**Output Formats**:
- `summary`: Human-readable overview
- `detailed`: Comprehensive analysis
- `json`: Machine-readable JSON
- `csv`: Spreadsheet format

**Examples**:
```bash
# Basic file analysis
ck metadata file.exe

# Detailed analysis
ck metadata suspicious.exe --format detailed

# Directory scan
ck metadata /downloads --recursive

# Security-focused scan
ck metadata /tmp --recursive --risk-only

# Export analysis
ck metadata file.pdf --format json --output report.json
ck metadata folder/ --format csv --output analysis.csv

# Large-scale analysis
ck metadata /home/user --recursive --max-files 1000 --max-size 50

# Filter by pattern
ck metadata /var/log --pattern "*.log" --recursive
```

**Analysis Components**:
1. **File Information**: Size, type, timestamps
2. **Content Analysis**: Entropy, patterns, strings
3. **Security Scanning**: Malware patterns, vulnerabilities
4. **Risk Assessment**: 0-100 risk score with recommendations

---

### 8. config - Configuration Management

**Purpose**: View and modify CryptoKit configuration settings.

**Usage**:
```bash
ck config ACTION [KEY] [VALUE]
```

**Actions**:
- `show`: Display all configuration
- `get KEY`: Get specific setting value
- `set KEY VALUE`: Set configuration value

**Configuration Categories**:
- `general.*`: General settings
- `encryption.*`: Encryption parameters
- `hashing.*`: Hashing settings
- `cracking.*`: Hash cracking configuration
- `steganography.*`: Steganography options
- `metadata.*`: File analysis settings
- `cli.*`: Interface preferences

**Examples**:
```bash
# Show all configuration
ck config show

# Get specific settings
ck config get encryption.default_algorithm
ck config get hashing.chunk_size
ck config get cli.colored_output

# Set configuration values
ck config set encryption.default_algorithm aes-128
ck config set hashing.default_algorithm sha256
ck config set cli.colored_output true
ck config set metadata.max_file_size 200MB
ck config set cracking.tools.hashcat.gpu_enabled false
```

**Common Configuration Keys**:
```yaml
# Encryption
encryption.default_algorithm: "aes-128"
encryption.iterations: 100000

# Hashing
hashing.default_algorithm: "sha256"
hashing.chunk_size: 65536

# CLI
cli.colored_output: true
cli.progress_bars: true
cli.interactive_mode: true

# Metadata Analysis
metadata.max_file_size: "100MB"
metadata.extract_strings: true
metadata.entropy_threshold: 7.5
```

---

### 9. interactive - Interactive Mode

**Purpose**: Start guided interactive mode.

**Usage**:
```bash
ck interactive
# or
ck i
```

**Features**:
- Menu-driven interface
- Guided parameter input
- Help system
- Safe operation with confirmations

**Interactive Commands**:
All main commands available with guided prompts:
- `encrypt` - Guided file encryption
- `decrypt` - Guided file decryption
- `hash` - Guided hashing
- `crack` - Guided hash analysis
- `hide` - Guided steganography
- `extract` - Guided data extraction
- `metadata` - Guided file analysis
- `config` - Configuration management
- `help` - Show command help
- `quit` - Exit interactive mode

**Example Session**:
```
$ ck interactive

CryptoKit (CK) - Interactive Mode
A comprehensive cryptography toolkit
Type 'help' for available commands or 'quit' to exit

CK> help
[Command table displayed]

CK> encrypt
Enter file path to encrypt: document.pdf
Select algorithm:
  1. aes-128
  2. 3des
Select algorithm (1-2): 1
Enter encryption password: [hidden]
Confirm password: [hidden]
Encrypting document.pdf with aes-128...
Encryption successful!
  Encrypted file: document.pdf.txt
  Key file: Key_document.pdf

CK> quit
Goodbye!
```

## Error Handling

### Common Error Messages

**File Not Found**:
```
Error: File not found: /path/to/file
```

**Permission Denied**:
```
Error: Permission denied accessing: /path/to/file
```

**Invalid Algorithm**:
```
Error: Unsupported algorithm: invalid_algo
Available algorithms: aes-128, 3des
```

**Invalid Hash**:
```
Error: Invalid hash format or length
```

**Insufficient Capacity**:
```
Error: Secret file too large. Maximum capacity: 65536 bytes
```

### Exit Codes

- `0`: Success
- `1`: General error
- `2`: Invalid arguments
- `3`: File not found
- `4`: Permission denied
- `5`: Cryptographic error

## Performance Tips

### Large Files
- Use appropriate chunk sizes for hashing
- Enable parallel processing for directories
- Set reasonable file size limits

### Memory Usage
- Monitor memory usage with large files
- Use streaming operations when possible
- Configure appropriate buffer sizes

### Security Best Practices
- Use strong passwords (>12 characters)
- Verify file integrity with hashes
- Store key files securely
- Use secure deletion for sensitive files

## Configuration Files

### Locations
1. **System**: `/etc/ck/config.yaml`
2. **User**: `~/.ck/config.yaml`
3. **Local**: `./config/default.yaml`
4. **Custom**: Specified with `--config`

### Format
```yaml
general:
  log_level: "INFO"
  temp_dir: "/tmp/ck"

encryption:
  default_algorithm: "aes-128"
  iterations: 100000

hashing:
  default_algorithm: "sha256"
  parallel_processing: true

cli:
  colored_output: true
  interactive_mode: true
```

## Environment Variables

- `CK_CONFIG_PATH`: Override config file location
- `CK_LOG_LEVEL`: Override log level
- `CK_TEMP_DIR`: Override temporary directory

## Troubleshooting

### Installation Issues
```bash
# Check Python version
python3 --version

# Verify dependencies
pip list | grep -E "(cryptography|Pillow|PyYAML|rich)"

# Reinstall
pip install --force-reinstall -r requirements.txt
```

### Runtime Issues
```bash
# Enable debug logging
ck --log-level DEBUG command args

# Check permissions
ls -la /path/to/file

# Verify file integrity
file /path/to/file
```

### Performance Issues
```bash
# Check available memory
free -h

# Monitor process
top -p $(pgrep -f "ck")

# Check disk space
df -h
```

This comprehensive help guide covers all aspects of using CryptoKit effectively and troubleshooting common issues.
