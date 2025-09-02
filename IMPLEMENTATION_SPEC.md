# CryptoKit (CK) - Detailed Implementation Specification

## Development Environment Setup

### Windows Development for Linux Target

#### Development Workflow
1. **Primary Development**: Windows VS Code
2. **Testing Environment**: WSL2 or Linux VM
3. **Target Deployment**: Linux CLI systems
4. **Cross-Platform Considerations**:
   - Use `pathlib.Path` for all file operations
   - Unix-style path separators in configurations
   - Platform-specific external tool paths
   - Environment variable handling differences

#### Required Tools on Windows
```powershell
# Python installation
py --version  # Should be 3.9+

# Required packages for development
py -m pip install PyYAML rich cryptography pytest black flake8 mypy

# Optional: WSL2 for Linux testing
wsl --install Ubuntu
```

#### Testing Strategy
- **Unit Tests**: Run on Windows during development
- **Integration Tests**: Linux VM or WSL2
- **Final Validation**: Actual Linux systems
- **Performance Tests**: Target platform only

## Phase 1: Symmetric Encryption - Detailed Implementation

### Overview
Phase 1 implements symmetric encryption algorithms with secure key management and file operations. The implementation focuses on security, performance, and usability.

### 1.1 Algorithm Implementation Architecture

#### Base Algorithm Interface
```python
# File: ck/encryption/interfaces.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pathlib import Path

class SymmetricAlgorithm(ABC):
    """Base interface for symmetric encryption algorithms"""
    
    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes, 
                iv: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Encrypt plaintext data
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key
            iv: Initialization vector (generated if None)
            
        Returns:
            Dict containing 'ciphertext', 'iv', 'tag' (if authenticated)
        """
        pass
    
    @abstractmethod  
    def decrypt(self, ciphertext: bytes, key: bytes,
                iv: bytes, tag: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext data
        
        Args:
            ciphertext: Encrypted data
            key: Decryption key  
            iv: Initialization vector
            tag: Authentication tag (if authenticated encryption)
            
        Returns:
            Decrypted plaintext
        """
        pass
    
    @property
    @abstractmethod
    def key_size(self) -> int:
        """Key size in bytes"""
        pass
    
    @property
    @abstractmethod
    def iv_size(self) -> int:
        """IV size in bytes"""
        pass
```

#### Algorithm Registry System
```python
# File: ck/encryption/registry.py
class AlgorithmRegistry:
    """Registry for symmetric encryption algorithms"""
    
    def __init__(self):
        self._algorithms: Dict[str, Type[SymmetricAlgorithm]] = {}
        self._register_builtin_algorithms()
    
    def register(self, name: str, algorithm_class: Type[SymmetricAlgorithm]):
        """Register an algorithm implementation"""
        self._algorithms[name] = algorithm_class
    
    def get_algorithm(self, name: str) -> SymmetricAlgorithm:
        """Get algorithm instance by name"""
        if name not in self._algorithms:
            raise ValueError(f"Unknown algorithm: {name}")
        return self._algorithms[name]()
    
    def list_algorithms(self) -> List[str]:
        """List available algorithm names"""
        return list(self._algorithms.keys())
```

### 1.2 AES Implementation Details

#### AES-256-GCM Implementation
```python
# File: ck/encryption/algorithms/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

class AES256GCM(SymmetricAlgorithm):
    """AES-256-GCM authenticated encryption"""
    
    def __init__(self):
        self.algorithm_name = "aes-256-gcm"
        self.key_length = 32  # 256 bits
        self.iv_length = 12   # 96 bits for GCM
        self.tag_length = 16  # 128 bits
    
    def encrypt(self, plaintext: bytes, key: bytes, 
                iv: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Encrypt using AES-256-GCM
        
        Process:
        1. Validate key size (must be 32 bytes)
        2. Generate IV if not provided (12 random bytes)
        3. Create AES-GCM cipher with key and IV
        4. Encrypt plaintext and generate authentication tag
        5. Return encrypted data with metadata
        """
        if len(key) != self.key_length:
            raise ValueError(f"Invalid key size: expected {self.key_length}, got {len(key)}")
        
        if iv is None:
            iv = os.urandom(self.iv_length)
        elif len(iv) != self.iv_length:
            raise ValueError(f"Invalid IV size: expected {self.iv_length}, got {len(iv)}")
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'tag': encryptor.tag,
            'algorithm': self.algorithm_name
        }
    
    def decrypt(self, ciphertext: bytes, key: bytes,
                iv: bytes, tag: Optional[bytes] = None) -> bytes:
        """
        Decrypt using AES-256-GCM
        
        Process:
        1. Validate inputs (key, IV, tag sizes)
        2. Create AES-GCM cipher with key and IV
        3. Set authentication tag
        4. Decrypt and verify authentication
        5. Return plaintext or raise authentication error
        """
        if len(key) != self.key_length:
            raise ValueError("Invalid key size")
        if len(iv) != self.iv_length:
            raise ValueError("Invalid IV size")
        if tag is None or len(tag) != self.tag_length:
            raise ValueError("Invalid or missing authentication tag")
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt and verify
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
```

### 1.3 Key Derivation Implementation

#### PBKDF2 Key Derivation
```python
# File: ck/encryption/key_derivation.py
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

class KeyDerivation:
    """Key derivation functions for password-based encryption"""
    
    @staticmethod
    def pbkdf2_derive(password: str, salt: bytes, 
                     key_length: int = 32, iterations: int = 100000) -> bytes:
        """
        Derive key using PBKDF2-HMAC-SHA256
        
        Process:
        1. Convert password to bytes (UTF-8)
        2. Validate salt length (minimum 16 bytes)
        3. Create PBKDF2HMAC instance with SHA256
        4. Derive key with specified iterations
        5. Return derived key bytes
        
        Security considerations:
        - Minimum 100,000 iterations (OWASP 2023 recommendation)
        - Salt must be cryptographically random
        - Key length should match algorithm requirements
        """
        if len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes")
        
        if iterations < 100000:
            raise ValueError("Iterations must be at least 100,000")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """Generate cryptographically secure random salt"""
        return os.urandom(length)
```

### 1.4 File Operations Implementation

#### Encryption Manager
```python
# File: ck/encryption/manager.py
from pathlib import Path
from typing import Optional, Callable, Dict, Any
import json

class EncryptionManager:
    """High-level encryption operations manager"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.registry = AlgorithmRegistry()
        self.key_derivation = KeyDerivation()
    
    def encrypt_file(self, input_path: Path, output_path: Path,
                    password: str, algorithm: str = None,
                    progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Encrypt a single file
        
        Process:
        1. Validate input file exists and is readable
        2. Select encryption algorithm (from config if not specified)
        3. Generate salt and derive key from password
        4. Read file in chunks to handle large files
        5. Encrypt each chunk and write to output
        6. Create metadata file with encryption parameters
        7. Return operation summary
        
        File format:
        - .ck extension added to encrypted files
        - Metadata stored in separate .ck.meta file
        - Binary format: [salt][iv][tag][encrypted_data]
        """
        # Validation
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        if not input_path.is_file():
            raise ValueError(f"Input path is not a file: {input_path}")
        
        # Algorithm selection
        if algorithm is None:
            algorithm = self.config.get_setting('encryption.default_algorithm')
        
        algo_impl = self.registry.get_algorithm(algorithm)
        
        # Key derivation
        salt = self.key_derivation.generate_salt()
        key = self.key_derivation.pbkdf2_derive(password, salt, algo_impl.key_size)
        
        # File encryption
        file_size = input_path.stat().st_size
        chunk_size = self.config.get_setting('encryption.chunk_size', 65536)
        
        with open(input_path, 'rb') as infile, \
             open(output_path, 'wb') as outfile:
            
            # Write metadata header
            self._write_file_header(outfile, salt, algorithm)
            
            bytes_processed = 0
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                
                # Encrypt chunk
                encrypted = algo_impl.encrypt(chunk, key)
                
                # Write encrypted chunk with size prefix
                self._write_encrypted_chunk(outfile, encrypted)
                
                bytes_processed += len(chunk)
                
                # Progress callback
                if progress_callback:
                    progress_callback(bytes_processed, file_size)
        
        # Create metadata file
        metadata = {
            'algorithm': algorithm,
            'file_size': file_size,
            'chunk_size': chunk_size,
            'encrypted_at': datetime.utcnow().isoformat(),
            'version': '1.0'
        }
        
        meta_path = Path(str(output_path) + '.meta')
        with open(meta_path, 'w') as meta_file:
            json.dump(metadata, meta_file, indent=2)
        
        return {
            'status': 'success',
            'input_file': str(input_path),
            'output_file': str(output_path),
            'metadata_file': str(meta_path),
            'algorithm': algorithm,
            'file_size': file_size
        }
```

#### Directory Encryption
```python
def encrypt_directory(self, input_dir: Path, output_dir: Path,
                     password: str, algorithm: str = None,
                     progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
    """
    Encrypt entire directory recursively
    
    Process:
    1. Validate input directory exists
    2. Create output directory structure
    3. Walk directory tree and collect all files
    4. Encrypt each file maintaining directory structure
    5. Create directory manifest with file mappings
    6. Handle symbolic links and permissions
    7. Return comprehensive operation summary
    
    Directory structure preservation:
    - Original directory structure maintained
    - File paths stored in manifest
    - Permissions and timestamps preserved in metadata
    - Symlinks handled according to configuration
    """
    if not input_dir.exists() or not input_dir.is_dir():
        raise ValueError(f"Input directory not found: {input_dir}")
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Collect all files
    file_list = []
    for file_path in input_dir.rglob('*'):
        if file_path.is_file():
            relative_path = file_path.relative_to(input_dir)
            file_list.append((file_path, relative_path))
    
    total_files = len(file_list)
    processed_files = 0
    failed_files = []
    
    # Process each file
    for input_file, relative_path in file_list:
        try:
            output_file = output_dir / relative_path
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Add .ck extension
            encrypted_file = output_file.with_suffix(output_file.suffix + '.ck')
            
            # Encrypt file
            result = self.encrypt_file(input_file, encrypted_file, password, algorithm)
            
            processed_files += 1
            
            if progress_callback:
                progress_callback(processed_files, total_files, f"Encrypted: {relative_path}")
                
        except Exception as e:
            failed_files.append({
                'file': str(relative_path),
                'error': str(e)
            })
    
    # Create directory manifest
    manifest = {
        'encryption_info': {
            'algorithm': algorithm or self.config.get_setting('encryption.default_algorithm'),
            'encrypted_at': datetime.utcnow().isoformat(),
            'version': '1.0'
        },
        'directory_info': {
            'original_path': str(input_dir),
            'total_files': total_files,
            'processed_files': processed_files,
            'failed_files': len(failed_files)
        },
        'failed_files': failed_files
    }
    
    manifest_path = output_dir / 'ck_manifest.json'
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    return {
        'status': 'completed',
        'total_files': total_files,
        'processed_files': processed_files,
        'failed_files': failed_files,
        'manifest_file': str(manifest_path)
    }
```

### 1.5 CLI Integration

#### Encryption Commands Implementation
```python
# File: ck/cli/commands/encrypt.py
def handle_encrypt_command(args, config, logger):
    """
    Handle encryption command from CLI
    
    User interaction flow:
    1. Parse command arguments (file/directory path, algorithm, output)
    2. Validate paths and permissions
    3. Prompt for password securely (no echo)
    4. Confirm operation details with user
    5. Initialize progress tracking
    6. Execute encryption operation
    7. Display results and save operation log
    
    Command examples:
    ck encrypt /path/to/file.txt --algorithm aes-256-gcm --output /path/to/encrypted/
    ck encrypt /path/to/directory/ --algorithm chacha20-poly1305
    """
    from ck.encryption.manager import EncryptionManager
    from getpass import getpass
    from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
    
    # Initialize encryption manager
    manager = EncryptionManager(config)
    
    # Parse target path
    target_path = Path(args.target)
    if not target_path.exists():
        logger.error(f"Target path does not exist: {target_path}")
        return 1
    
    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        if target_path.is_file():
            output_path = target_path.with_suffix(target_path.suffix + '.ck')
        else:
            output_path = target_path.parent / (target_path.name + '_encrypted')
    
    # Get password securely
    password = getpass("Enter encryption password: ")
    if not password:
        logger.error("Password cannot be empty")
        return 1
    
    # Confirm password
    confirm_password = getpass("Confirm password: ")
    if password != confirm_password:
        logger.error("Passwords do not match")
        return 1
    
    # Display operation summary
    print(f"Encryption Operation Summary:")
    print(f"  Target: {target_path}")
    print(f"  Output: {output_path}")
    print(f"  Algorithm: {args.algorithm}")
    print(f"  Type: {'File' if target_path.is_file() else 'Directory'}")
    
    confirm = input("Proceed with encryption? (y/N): ").lower()
    if confirm != 'y':
        print("Operation cancelled")
        return 0
    
    # Execute encryption with progress tracking
    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            if target_path.is_file():
                task = progress.add_task("Encrypting file...", total=target_path.stat().st_size)
                
                def progress_callback(current, total, message=""):
                    progress.update(task, completed=current, description=message or "Encrypting...")
                
                result = manager.encrypt_file(target_path, output_path, password, 
                                            args.algorithm, progress_callback)
            else:
                # Directory encryption
                task = progress.add_task("Encrypting directory...", total=None)
                
                def progress_callback(current, total, message=""):
                    progress.update(task, completed=current, total=total, description=message)
                
                result = manager.encrypt_directory(target_path, output_path, password,
                                                 args.algorithm, progress_callback)
        
        # Display results
        print(f"Encryption completed successfully!")
        print(f"Output: {result['output_file'] if 'output_file' in result else output_path}")
        if 'failed_files' in result and result['failed_files']:
            print(f"Warning: {len(result['failed_files'])} files failed to encrypt")
        
        logger.info(f"Encryption completed: {target_path} -> {output_path}")
        return 0
        
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        print(f"Error: {e}")
        return 1
```

### 1.6 User Interaction Patterns

#### Password Management
```python
# File: ck/core/security.py
class SecurePasswordManager:
    """Secure password handling utilities"""
    
    @staticmethod
    def get_password_with_strength_check(prompt: str = "Enter password: ") -> str:
        """
        Get password with strength validation
        
        User interaction:
        1. Prompt for password (hidden input)
        2. Validate password strength
        3. Display strength feedback
        4. Require confirmation for weak passwords
        5. Confirm password entry
        """
        import getpass
        import re
        
        while True:
            password = getpass.getpass(prompt)
            
            if not password:
                print("Password cannot be empty")
                continue
            
            # Password strength check
            strength = PasswordStrengthChecker.check_strength(password)
            
            if strength['score'] < 3:
                print(f"Password strength: {strength['level']}")
                for suggestion in strength['suggestions']:
                    print(f"  - {suggestion}")
                
                continue_weak = input("Use weak password anyway? (y/N): ").lower()
                if continue_weak != 'y':
                    continue
            
            # Confirm password
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match")
                continue
            
            return password
```

#### Interactive Mode Enhancements
```python
# File: ck/cli/interactive.py
class InteractiveMode:
    """Enhanced interactive mode for user-friendly operation"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.console = Console()
    
    def run_encryption_wizard(self):
        """
        Step-by-step encryption wizard
        
        User flow:
        1. Welcome and explanation
        2. File/directory selection with validation
        3. Algorithm selection with descriptions
        4. Password setup with strength checking
        5. Output location selection
        6. Operation confirmation with summary
        7. Execution with progress tracking
        8. Results display and next steps
        """
        self.console.print(Panel.fit(
            "Encryption Wizard\n"
            "This wizard will guide you through encrypting files or directories.",
            border_style="blue"
        ))
        
        # Step 1: Target selection
        while True:
            target_path = Prompt.ask("Enter path to file or directory to encrypt")
            target = Path(target_path)
            
            if not target.exists():
                self.console.print(f"[red]Path does not exist: {target_path}[/red]")
                continue
            
            if target.is_file():
                self.console.print(f"[green]Selected file: {target.name}[/green]")
                self.console.print(f"Size: {self._format_size(target.stat().st_size)}")
            else:
                file_count = len(list(target.rglob('*')))
                self.console.print(f"[green]Selected directory: {target.name}[/green]")
                self.console.print(f"Contains: {file_count} files")
            
            confirm = Confirm.ask("Use this target?")
            if confirm:
                break
        
        # Step 2: Algorithm selection
        algorithms = self._get_available_algorithms()
        algorithm_choice = self._select_algorithm(algorithms)
        
        # Step 3: Password setup
        password = SecurePasswordManager.get_password_with_strength_check()
        
        # Step 4: Output location
        output_path = self._select_output_location(target)
        
        # Step 5: Operation summary and confirmation
        self._display_operation_summary(target, output_path, algorithm_choice)
        
        if not Confirm.ask("Proceed with encryption?"):
            self.console.print("[yellow]Operation cancelled[/yellow]")
            return
        
        # Step 6: Execute encryption
        self._execute_encryption_with_progress(target, output_path, password, algorithm_choice)
```

### 1.7 Testing Strategy

#### Unit Test Structure
```python
# File: tests/unit/encryption/test_aes.py
class TestAES256GCM(unittest.TestCase):
    """Comprehensive tests for AES-256-GCM implementation"""
    
    def setUp(self):
        self.algorithm = AES256GCM()
        self.test_key = os.urandom(32)  # 256-bit key
        self.test_data = b"Hello, World! This is test data for encryption."
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test basic encryption/decryption roundtrip"""
        # Encrypt
        result = self.algorithm.encrypt(self.test_data, self.test_key)
        
        # Verify structure
        self.assertIn('ciphertext', result)
        self.assertIn('iv', result)
        self.assertIn('tag', result)
        
        # Decrypt
        decrypted = self.algorithm.decrypt(
            result['ciphertext'], 
            self.test_key,
            result['iv'],
            result['tag']
        )
        
        # Verify
        self.assertEqual(self.test_data, decrypted)
    
    def test_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertext"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        
        result1 = self.algorithm.encrypt(self.test_data, key1)
        result2 = self.algorithm.encrypt(self.test_data, key2)
        
        self.assertNotEqual(result1['ciphertext'], result2['ciphertext'])
    
    def test_invalid_key_size_raises_error(self):
        """Test that invalid key sizes raise appropriate errors"""
        invalid_key = os.urandom(16)  # 128-bit key for 256-bit algorithm
        
        with self.assertRaises(ValueError):
            self.algorithm.encrypt(self.test_data, invalid_key)
    
    def test_authentication_tag_verification(self):
        """Test that tampered ciphertext fails authentication"""
        result = self.algorithm.encrypt(self.test_data, self.test_key)
        
        # Tamper with ciphertext
        tampered_ciphertext = bytearray(result['ciphertext'])
        tampered_ciphertext[0] ^= 1
        
        with self.assertRaises(Exception):  # Should raise authentication error
            self.algorithm.decrypt(
                bytes(tampered_ciphertext),
                self.test_key,
                result['iv'],
                result['tag']
            )
```

#### Integration Test Structure
```python
# File: tests/integration/test_file_encryption.py
class TestFileEncryption(unittest.TestCase):
    """Integration tests for file encryption operations"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = ConfigManager()
        self.manager = EncryptionManager(self.config)
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_large_file_encryption(self):
        """Test encryption of large files (>100MB)"""
        # Create large test file
        large_file = Path(self.temp_dir) / "large_test.txt"
        with open(large_file, 'wb') as f:
            for _ in range(1024):  # 100MB file
                f.write(os.urandom(100 * 1024))
        
        # Encrypt
        encrypted_file = large_file.with_suffix('.ck')
        result = self.manager.encrypt_file(
            large_file, encrypted_file, "test_password"
        )
        
        # Verify
        self.assertEqual(result['status'], 'success')
        self.assertTrue(encrypted_file.exists())
        
        # Decrypt and verify
        decrypted_file = large_file.with_suffix('.decrypted')
        decrypt_result = self.manager.decrypt_file(
            encrypted_file, decrypted_file, "test_password"
        )
        
        # Compare files
        self.assertTrue(filecmp.cmp(large_file, decrypted_file))
```

This detailed specification provides the foundation for implementing Phase 1 with professional standards, cross-platform considerations, and comprehensive user interaction patterns. The implementation focuses on security, usability, and maintainability while considering the Windows development environment targeting Linux deployment.
