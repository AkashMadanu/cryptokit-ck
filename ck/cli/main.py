"""
Main CLI entry point for CryptoKit (CK)

Simple, fast, and easy-to-use cryptographic toolkit.
"""

import sys
import argparse
import os
import getpass
import hashlib
from typing import List, Optional
from pathlib import Path

# Add the project root to the Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Suppress all logging by default for clean output
import logging
logging.getLogger().setLevel(logging.CRITICAL)


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="ck",
        description="CryptoKit (CK) - Simple Cryptography Toolkit"
    )
    
    parser.add_argument("--version", action="version", version="CryptoKit (CK) 0.1.0")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Interactive mode
    subparsers.add_parser("interactive", help="Start interactive mode", aliases=["i"])
    
    # Encryption
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt files", aliases=["e"])
    encrypt_parser.add_argument("file", help="File to encrypt")
    encrypt_parser.add_argument("--algo", "-a", choices=["3des", "aes-128"], default="aes-128")
    encrypt_parser.add_argument("--password", "-p", help="Password")
    
    # Decryption
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt files", aliases=["d"])
    decrypt_parser.add_argument("file", help="Encrypted file")
    decrypt_parser.add_argument("--password", "-p", help="Password")
    
    # Hashing
    hash_parser = subparsers.add_parser("hash", help="Generate multiple hashes", aliases=["h"])
    hash_parser.add_argument("file", help="File to hash")
    
    # Steganography
    hide_parser = subparsers.add_parser("hide", help="Hide data in image")
    hide_parser.add_argument("image", help="Cover image")
    hide_parser.add_argument("data", help="Text file to hide")
    hide_parser.add_argument("output", help="Output image")
    hide_parser.add_argument("--password", "-p", help="Password")
    
    extract_parser = subparsers.add_parser("extract", help="Extract data from image")
    extract_parser.add_argument("image", help="Image with hidden data")
    extract_parser.add_argument("--password", "-p", help="Password")
    
    # Metadata
    meta_parser = subparsers.add_parser("metadata", help="Show file details")
    meta_parser.add_argument("file", help="File to analyze")
    
    return parser


def run_interactive():
    """Run interactive mode with numbered options."""
    print("\n" + "="*50)
    print("         CryptoKit Interactive Mode")
    print("="*50)
    
    while True:
        print("\nSelect an option:")
        print("1. Encrypt file")
        print("2. Decrypt file") 
        print("3. Generate hashes")
        print("4. Hide data in image")
        print("5. Extract data from image")
        print("6. File metadata")
        print("7. Exit")
        
        choice = input("\nEnter choice (1-7): ").strip()
        
        if choice == "1":
            handle_interactive_encrypt()
        elif choice == "2":
            handle_interactive_decrypt()
        elif choice == "3":
            handle_interactive_hash()
        elif choice == "4":
            handle_interactive_hide()
        elif choice == "5":
            handle_interactive_extract()
        elif choice == "6":
            handle_interactive_metadata()
        elif choice == "7":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1-7.")


def handle_interactive_encrypt():
    """Handle interactive encryption."""
    filename = input("Enter file to encrypt: ").strip()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
        
    print("\nAlgorithms:")
    print("1. AES-128 (recommended)")
    print("2. 3DES")
    
    algo_choice = input("Select algorithm (1-2): ").strip()
    algo = "aes-128" if algo_choice == "1" else "3des"
    
    password = getpass.getpass("Enter password: ")
    encrypt_file_simple(filename, algo, password)


def handle_interactive_decrypt():
    """Handle interactive decryption."""
    filename = input("Enter encrypted file: ").strip()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
        
    password = getpass.getpass("Enter password: ")
    decrypt_file_simple(filename, password)


def handle_interactive_hash():
    """Handle interactive hashing."""
    filename = input("Enter file to hash: ").strip()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
    
    generate_multiple_hashes(filename)


def handle_interactive_hide():
    """Handle interactive steganography hiding."""
    image = input("Enter cover image: ").strip()
    data_file = input("Enter text file to hide: ").strip()
    output = input("Enter output image name: ").strip()
    password = getpass.getpass("Enter password (optional): ")
    
    if not os.path.exists(image):
        print(f"Error: Image '{image}' not found")
        return
    if not os.path.exists(data_file):
        print(f"Error: Data file '{data_file}' not found")
        return
        
    hide_data_simple(image, data_file, output, password)


def handle_interactive_extract():
    """Handle interactive steganography extraction."""
    image = input("Enter image with hidden data: ").strip()
    password = getpass.getpass("Enter password: ")
    
    if not os.path.exists(image):
        print(f"Error: Image '{image}' not found")
        return
        
    extract_data_simple(image, password)


def handle_interactive_metadata():
    """Handle interactive metadata analysis."""
    filename = input("Enter file to analyze: ").strip()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        return
        
    show_file_metadata(filename)


def encrypt_file_simple(filename: str, algorithm: str, password: str):
    """Simple encryption with custom output naming."""
    try:
        from ck.services.symmetric import SymmetricService
        
        if not password:
            password = getpass.getpass("Enter password: ")
        
        service = SymmetricService()
        
        # Create output filename: demo.txt -> demoEncrypt.txt
        path = Path(filename)
        base_name = path.stem
        extension = path.suffix
        output_file = f"{base_name}Encrypt{extension}"
        
        service.encrypt_file(
            input_file=filename,
            output_file=output_file,
            algorithm=algorithm,
            password=password
        )
        
        print(f"File encrypted successfully: {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")


def decrypt_file_simple(filename: str, password: str):
    """Simple decryption with password."""
    try:
        from ck.services.symmetric import SymmetricService
        
        if not password:
            password = getpass.getpass("Enter password: ")
        
        service = SymmetricService()
        
        # Create output filename: demoEncrypt.txt -> demoDecrypt.txt
        path = Path(filename)
        if "Encrypt" in path.stem:
            base_name = path.stem.replace("Encrypt", "Decrypt")
        else:
            base_name = path.stem + "Decrypt"
        
        extension = path.suffix
        output_file = f"{base_name}{extension}"
        
        service.decrypt_file(
            input_file=filename,
            output_file=output_file,
            password=password
        )
        
        print(f"File decrypted successfully: {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")


def generate_multiple_hashes(filename: str):
    """Generate multiple hashes for a file."""
    try:
        algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']
        
        with open(filename, 'rb') as f:
            data = f.read()
        
        print(f"\nHashes for file: {filename}")
        print("-" * 50)
        
        for algo in algorithms:
            if algo == 'md5':
                hash_obj = hashlib.md5(data)
            elif algo == 'sha1':
                hash_obj = hashlib.sha1(data)
            elif algo == 'sha256':
                hash_obj = hashlib.sha256(data)
            elif algo == 'sha512':
                hash_obj = hashlib.sha512(data)
            elif algo == 'blake2b':
                hash_obj = hashlib.blake2b(data)
            
            hash_value = hash_obj.hexdigest()
            print(f"{algo.upper():<10}: {hash_value}")
        
    except Exception as e:
        print(f"Error: {e}")


def hide_data_simple(image: str, data_file: str, output: str, password: str):
    """Simple steganography hiding with clean output."""
    try:
        from ck.services.steganography import SteganographyService
        
        service = SteganographyService()
        
        # Get cover file info
        cover_capacity = service.analyze_capacity(image)
        
        with open(data_file, 'rb') as f:
            secret_size = len(f.read())
        
        print(f"Cover file: {image}")
        print(f"Method: LSB Image Steganography")
        print(f"Capacity: {cover_capacity['capacity_bytes']} bytes")
        print(f"Secret file size: {secret_size} bytes")
        print(f"Hiding {data_file} in {image}...")
        
        service.hide_data(
            cover_file=image,
            secret_file=data_file,
            output_file=output,
            password=password
        )
        
        print("File hidden successfully")
        
    except Exception as e:
        print(f"Error: {e}")


def extract_data_simple(image: str, password: str):
    """Simple steganography extraction with clean output."""
    try:
        from ck.services.steganography import SteganographyService
        
        service = SteganographyService()
        
        print(f"Extracting data from {image}...")
        
        extracted_data = service.extract_data(
            stego_file=image,
            password=password
        )
        
        if isinstance(extracted_data, bytes):
            try:
                content = extracted_data.decode('utf-8')
                print(f"Content: {content}")
            except:
                print(f"Extracted {len(extracted_data)} bytes of binary data")
        
    except Exception as e:
        print(f"Error: {e}")


def show_file_metadata(filename: str):
    """Show simple file metadata like exiftool."""
    try:
        path = Path(filename)
        stat = path.stat()
        
        print(f"\nFile Details: {filename}")
        print("-" * 50)
        print(f"File Name     : {path.name}")
        print(f"File Size     : {stat.st_size} bytes")
        print(f"File Type     : {path.suffix.upper().replace('.', '') if path.suffix else 'Unknown'}")
        print(f"Created       : {stat.st_ctime}")
        print(f"Modified      : {stat.st_mtime}")
        print(f"Permissions   : {oct(stat.st_mode)[-3:]}")
        
        # Try to detect MIME type
        try:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                print(f"MIME Type     : {mime_type}")
        except:
            pass
            
    except Exception as e:
        print(f"Error: {e}")


def main():
    """Main entry point."""
    parser = create_parser()
    
    if len(sys.argv) == 1:
        # No arguments, start interactive mode
        run_interactive()
        return
    
    args = parser.parse_args()
    
    # Enable verbose logging if requested
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    if args.command in ["interactive", "i"]:
        run_interactive()
    
    elif args.command in ["encrypt", "e"]:
        encrypt_file_simple(args.file, args.algo, args.password)
    
    elif args.command in ["decrypt", "d"]:
        decrypt_file_simple(args.file, args.password)
    
    elif args.command in ["hash", "h"]:
        generate_multiple_hashes(args.file)
    
    elif args.command == "hide":
        hide_data_simple(args.image, args.data, args.output, args.password)
    
    elif args.command == "extract":
        extract_data_simple(args.image, args.password)
    
    elif args.command == "metadata":
        show_file_metadata(args.file)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
