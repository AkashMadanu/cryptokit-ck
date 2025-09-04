"""
Main CLI entry point for CryptoKit (CK)

Provides the primary command-line interface for all cryptographic operations.
"""

import sys
import argparse
from typing import List, Optional
from pathlib import Path

# Add the project root to the Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from ck.core.config import ConfigManager
from ck.core.logger import setup_logger
from ck.core.exceptions import CKException


def create_parser() -> argparse.ArgumentParser:
    """
    Create the main argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="ck",
        description="CryptoKit (CK) - Comprehensive Cryptography Toolkit",
        epilog="For more information about specific commands, use: ck <command> --help"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="CryptoKit (CK) 0.1.0-alpha"
    )
    
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Configuration file path"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output (log to file only)"
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
        metavar="COMMAND"
    )
    
    # Interactive mode (default when no command specified)
    subparsers.add_parser(
        "interactive",
        help="Start interactive mode",
        aliases=["i"]
    )
    
    # Configuration commands
    config_parser = subparsers.add_parser(
        "config",
        help="Configuration management"
    )
    config_subparsers = config_parser.add_subparsers(
        dest="config_action",
        help="Configuration actions"
    )
    
    config_subparsers.add_parser("show", help="Show current configuration")
    
    set_parser = config_subparsers.add_parser("set", help="Set configuration value")
    set_parser.add_argument("key", help="Configuration key (dot notation)")
    set_parser.add_argument("value", help="Configuration value")
    
    get_parser = config_subparsers.add_parser("get", help="Get configuration value")
    get_parser.add_argument("key", help="Configuration key (dot notation)")
    
    # Encryption commands
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt files using symmetric algorithms",
        aliases=["enc", "e"]
    )
    encrypt_parser.add_argument(
        "file",
        help="File to encrypt"
    )
    encrypt_parser.add_argument(
        "--algorithm", "-a",
        choices=["3des", "aes-128"],
        help="Encryption algorithm (will prompt if not provided)"
    )
    encrypt_parser.add_argument(
        "--output", "-o",
        help="Output file path (default: input_file.txt)"
    )
    encrypt_parser.add_argument(
        "--password", "-p",
        help="Encryption password (will prompt if not provided)"
    )
    encrypt_parser.add_argument(
        "--key-file", "-k",
        help="Use existing key file instead of generating new one"
    )
    
    # Decryption commands
    decrypt_parser = subparsers.add_parser(
        "decrypt", 
        help="Decrypt files using symmetric algorithms",
        aliases=["dec", "d"]
    )
    decrypt_parser.add_argument(
        "file",
        help="Encrypted file to decrypt (.txt)"
    )
    decrypt_parser.add_argument(
        "--key-file", "-k",
        required=True,
        help="Key file for decryption"
    )
    decrypt_parser.add_argument(
        "--output", "-o", 
        help="Output file path (default: remove .txt extension)"
    )
    
    # Hashing commands
    hash_parser = subparsers.add_parser(
        "hash",
        help="Generate hashes of files or directories",
        aliases=["h"]
    )
    hash_parser.add_argument(
        "target",
        help="File or directory to hash"
    )
    hash_parser.add_argument(
        "--algorithm", "-a",
        choices=["md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "blake2s"],
        default="sha256",
        help="Hash algorithm (default: sha256)"
    )
    hash_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save hash to file (print only)"
    )
    
    # Hash cracking commands
    crack_parser = subparsers.add_parser(
        "crack",
        help="Crack hashes using external tools"
    )
    crack_parser.add_argument(
        "hash_value",
        help="Hash value to crack"
    )
    crack_parser.add_argument(
        "--type", "-t",
        help="Hash type (auto-detect if not specified)"
    )
    crack_parser.add_argument(
        "--tool",
        choices=["john", "hashcat", "auto"],
        default="auto",
        help="Cracking tool to use (default: auto)"
    )
    crack_parser.add_argument(
        "--wordlist", "-w",
        help="Wordlist file to use"
    )
    crack_parser.add_argument(
        "--attack-mode", "-m",
        choices=["dictionary", "brute", "hybrid"],
        default="dictionary",
        help="Attack mode (default: dictionary)"
    )
    
    # Steganography commands
    hide_parser = subparsers.add_parser(
        "hide",
        help="Hide data in files using steganography"
    )
    hide_parser.add_argument("cover_file", help="Cover file (image, text, etc.)")
    hide_parser.add_argument("secret_file", help="File containing secret data")
    hide_parser.add_argument("output_file", help="Output file with hidden data")
    hide_parser.add_argument("--password", "-p", help="Password for encryption")
    hide_parser.add_argument("--method", "-m", choices=["lsb", "text", "binary"], 
                             default="lsb", help="Steganography method (default: lsb)")
    
    extract_parser = subparsers.add_parser(
        "extract", 
        help="Extract hidden data from steganography files"
    )
    extract_parser.add_argument("stego_file", help="File containing hidden data")
    extract_parser.add_argument("--output", "-o", help="Output file for extracted data")
    extract_parser.add_argument("--password", "-p", help="Password for decryption")
    extract_parser.add_argument("--method", "-m", choices=["lsb", "text", "binary"], 
                                help="Steganography method (auto-detect if not specified)")
    
    # Metadata commands
    meta_parser = subparsers.add_parser(
        "metadata",
        help="Extract and analyze file metadata",
        aliases=["meta"]
    )
    meta_parser.add_argument(
        "target",
        help="File or directory to analyze"
    )
    meta_parser.add_argument(
        "--output", "-o",
        help="Output file for metadata report"
    )
    meta_parser.add_argument(
        "--format",
        choices=["json", "yaml", "table"],
        default="table",
        help="Output format (default: table)"
    )
    
    return parser


def interactive_mode(config: ConfigManager, logger) -> None:
    """
    Start interactive mode for user-friendly operation.
    
    Args:
        config: Configuration manager
        logger: Logger instance
    """
    try:
        from rich.console import Console
        from rich.prompt import Prompt
        from rich.panel import Panel
        from rich.table import Table
        
        console = Console()
        
        # Display welcome message
        console.print(Panel.fit(
            "[bold cyan]CryptoKit (CK) - Interactive Mode[/bold cyan]\n"
            "A comprehensive cryptography toolkit\n"
            "Type 'help' for available commands or 'quit' to exit",
            border_style="cyan"
        ))
        
        while True:
            try:
                choice = Prompt.ask(
                    "\n[bold green]CK[/bold green]",
                    choices=[
                        "encrypt", "decrypt", "hash", "crack", 
                        "hide", "extract", "metadata", "config", "help", "quit"
                    ],
                    default="help"
                )
                
                if choice == "quit":
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                elif choice == "help":
                    show_interactive_help(console)
                elif choice == "config":
                    show_config_menu(console, config)
                elif choice == "encrypt":
                    handle_interactive_encrypt(console, config, logger)
                elif choice == "decrypt":
                    handle_interactive_decrypt(console, config, logger)
                else:
                    console.print(f"[yellow]'{choice}' functionality coming in Phase {get_phase_number(choice)}![/yellow]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Goodbye![/yellow]")
                break
            except Exception as e:
                logger.error(f"Error in interactive mode: {e}")
                console.print(f"[red]Error: {e}[/red]")
                
    except ImportError:
        # Fallback to simple interactive mode without rich
        print("CryptoKit (CK) - Interactive Mode")
        print("Type 'help' for available commands or 'quit' to exit")
        
        while True:
            try:
                choice = input("\nCK> ").strip().lower()
                
                if choice == "quit":
                    print("Goodbye!")
                    break
                elif choice == "help":
                    show_simple_help()
                elif choice == "config":
                    show_simple_config_menu(config)
                elif choice == "encrypt":
                    handle_simple_encrypt(config, logger)
                elif choice == "decrypt":
                    handle_simple_decrypt(config, logger)
                else:
                    print(f"'{choice}' functionality coming in Phase {get_phase_number(choice)}!")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                logger.error(f"Error in interactive mode: {e}")
                print(f"Error: {e}")


def show_interactive_help(console) -> None:
    """Show help in interactive mode with rich formatting."""
    try:
        from rich.table import Table
        
        table = Table(title="Available Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Status", style="green")
        
        commands = [
            ("encrypt", "Encrypt files with symmetric algorithms", "✅ Available"),
            ("decrypt", "Decrypt files with symmetric algorithms", "✅ Available"),
            ("hash", "Generate file hashes", "✅ Available"),
            ("crack", "Crack hash values", "🔴 Phase 3"),
            ("hide", "Hide data in files", "🔴 Phase 4"),
            ("extract", "Extract hidden data", "🔴 Phase 4"),
            ("metadata", "File metadata analysis", "🔴 Phase 5"),
            ("config", "Configuration management", "✅ Available"),
            ("help", "Show this help", "✅ Available"),
            ("quit", "Exit the program", "✅ Available"),
        ]
        
        for cmd, desc, status in commands:
            table.add_row(cmd, desc, status)
        
        console.print(table)
    except ImportError:
        show_simple_help()


def show_simple_help() -> None:
    """Show help in simple text format."""
    print("\nAvailable Commands:")
    print("  encrypt  - Encrypt files with symmetric algorithms (Available)")
    print("  decrypt  - Decrypt files with symmetric algorithms (Available)")
    print("  hash     - Generate file hashes (Available)")
    print("  crack    - Crack hash values (Phase 3)")
    print("  hide     - Hide data in files (Phase 4)")
    print("  extract  - Extract hidden data (Phase 4)")
    print("  metadata - File metadata analysis (Phase 5)")
    print("  config   - Configuration management (Available)")
    print("  help     - Show this help (Available)")
    print("  quit     - Exit the program (Available)")


def show_config_menu(console, config: ConfigManager) -> None:
    """Show configuration menu with rich formatting."""
    try:
        from rich.prompt import Prompt
        
        action = Prompt.ask(
            "Configuration action",
            choices=["show", "get", "set", "back"],
            default="show"
        )
        
        if action == "back":
            return
        elif action == "show":
            settings = config.get_all_settings()
            console.print_json(data=settings)
        elif action == "get":
            key = Prompt.ask("Configuration key")
            value = config.get_setting(key, "Not found")
            console.print(f"[cyan]{key}[/cyan]: [white]{value}[/white]")
        elif action == "set":
            key = Prompt.ask("Configuration key")
            value = Prompt.ask("Configuration value")
            config.set_setting(key, value)
            console.print(f"[green]Set {key} = {value}[/green]")
    except ImportError:
        show_simple_config_menu(config)


def show_simple_config_menu(config: ConfigManager) -> None:
    """Show configuration menu in simple text format."""
    print("Configuration actions: show, get, set, back")
    action = input("Action: ").strip().lower()
    
    if action == "back":
        return
    elif action == "show":
        settings = config.get_all_settings()
        import json
        print(json.dumps(settings, indent=2))
    elif action == "get":
        key = input("Configuration key: ").strip()
        value = config.get_setting(key, "Not found")
        print(f"{key}: {value}")
    elif action == "set":
        key = input("Configuration key: ").strip()
        value = input("Configuration value: ").strip()
        config.set_setting(key, value)
        print(f"Set {key} = {value}")


def handle_interactive_encrypt(console, config: ConfigManager, logger) -> None:
    """Handle encryption in interactive mode with rich formatting."""
    try:
        from rich.prompt import Prompt
        from pathlib import Path
        from getpass import getpass
        from ck.services.symmetric import SymmetricEncryptionService
        
        # Get input file
        file_path = Prompt.ask("Enter file path to encrypt")
        input_file = Path(file_path)
        
        if not input_file.exists():
            console.print(f"[red]Error: File not found: {input_file}[/red]")
            return
        
        # Initialize service and get algorithms
        service = SymmetricEncryptionService()
        available = service.get_available_algorithms()
        
        # Select algorithm
        algorithm = Prompt.ask(
            "Select algorithm",
            choices=available,
            default=available[0] if available else "aes-128"
        )
        
        # Get password
        console.print("Enter encryption password:")
        password = getpass()
        console.print("Confirm password:")
        confirm = getpass()
        
        if password != confirm:
            console.print("[red]Error: Passwords do not match.[/red]")
            return
        
        # Perform encryption
        console.print(f"Encrypting {input_file} with {algorithm}...")
        encrypted_file, key_file_path = service.encrypt_file(
            input_file=input_file,
            algorithm=algorithm,
            password=password
        )
        
        console.print("[green]Encryption successful![/green]")
        console.print(f"  Encrypted file: [cyan]{encrypted_file}[/cyan]")
        console.print(f"  Key file: [cyan]{key_file_path}[/cyan]")
        
    except ImportError:
        handle_simple_encrypt(config, logger)
    except Exception as e:
        logger.error(f"Interactive encryption failed: {e}")
        console.print(f"[red]Error: {e}[/red]")


def handle_simple_encrypt(config: ConfigManager, logger) -> None:
    """Handle encryption in simple interactive mode."""
    try:
        from pathlib import Path
        from getpass import getpass
        from ck.services.symmetric import SymmetricEncryptionService
        
        # Get input file
        file_path = input("Enter file path to encrypt: ").strip()
        input_file = Path(file_path)
        
        if not input_file.exists():
            print(f"Error: File not found: {input_file}")
            return
        
        # Initialize service and get algorithms
        service = SymmetricEncryptionService()
        available = service.get_available_algorithms()
        
        # Select algorithm
        print("Available algorithms:")
        for i, algo in enumerate(available, 1):
            print(f"  {i}. {algo}")
        
        while True:
            try:
                choice = input("Select algorithm (1-3): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(available):
                    algorithm = available[idx]
                    break
                else:
                    print("Invalid choice. Please select 1-3.")
            except ValueError:
                print("Invalid input. Please enter a number.")
        
        # Get password
        password = getpass("Enter encryption password: ")
        confirm = getpass("Confirm password: ")
        
        if password != confirm:
            print("Error: Passwords do not match.")
            return
        
        # Perform encryption
        print(f"Encrypting {input_file} with {algorithm}...")
        encrypted_file, key_file_path = service.encrypt_file(
            input_file=input_file,
            algorithm=algorithm,
            password=password
        )
        
        print("Encryption successful!")
        print(f"  Encrypted file: {encrypted_file}")
        print(f"  Key file: {key_file_path}")
        
    except Exception as e:
        logger.error(f"Simple encryption failed: {e}")
        print(f"Error: {e}")


def handle_interactive_decrypt(console, config: ConfigManager, logger) -> None:
    """Handle decryption in interactive mode with rich formatting."""
    try:
        from rich.prompt import Prompt
        from pathlib import Path
        from ck.services.symmetric import SymmetricEncryptionService
        
        # Get input files
        encrypted_path = Prompt.ask("Enter encrypted file path (.txt)")
        encrypted_file = Path(encrypted_path)
        
        if not encrypted_file.exists():
            console.print(f"[red]Error: Encrypted file not found: {encrypted_file}[/red]")
            return
        
        key_path = Prompt.ask("Enter key file path")
        key_file = Path(key_path)
        
        if not key_file.exists():
            console.print(f"[red]Error: Key file not found: {key_file}[/red]")
            return
        
        # Initialize service
        service = SymmetricEncryptionService()
        
        # Perform decryption
        console.print(f"Decrypting {encrypted_file}...")
        decrypted_file = service.decrypt_file(
            encrypted_file=encrypted_file,
            key_file=key_file
        )
        
        console.print("[green]Decryption successful![/green]")
        console.print(f"  Decrypted file: [cyan]{decrypted_file}[/cyan]")
        
    except ImportError:
        handle_simple_decrypt(config, logger)
    except Exception as e:
        logger.error(f"Interactive decryption failed: {e}")
        console.print(f"[red]Error: {e}[/red]")


def handle_simple_decrypt(config: ConfigManager, logger) -> None:
    """Handle decryption in simple interactive mode."""
    try:
        from pathlib import Path
        from ck.services.symmetric import SymmetricEncryptionService
        
        # Get input files
        encrypted_path = input("Enter encrypted file path (.txt): ").strip()
        encrypted_file = Path(encrypted_path)
        
        if not encrypted_file.exists():
            print(f"Error: Encrypted file not found: {encrypted_file}")
            return
        
        key_path = input("Enter key file path: ").strip()
        key_file = Path(key_path)
        
        if not key_file.exists():
            print(f"Error: Key file not found: {key_file}")
            return
        
        # Initialize service
        service = SymmetricEncryptionService()
        
        # Perform decryption
        print(f"Decrypting {encrypted_file}...")
        decrypted_file = service.decrypt_file(
            encrypted_file=encrypted_file,
            key_file=key_file
        )
        
        print("Decryption successful!")
        print(f"  Decrypted file: {decrypted_file}")
        
    except Exception as e:
        logger.error(f"Simple decryption failed: {e}")
        print(f"Error: {e}")


def get_phase_number(command: str) -> int:
    """Get the phase number for a command."""
    phase_map = {
        "encrypt": 1, "decrypt": 1,
        "hash": 2,
        "crack": 3,
        "hide": 4, "extract": 4,
        "metadata": 5
    }
    return phase_map.get(command, 1)


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.
    
    Args:
        argv: Command-line arguments (uses sys.argv if None)
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        # Parse arguments
        parser = create_parser()
        args = parser.parse_args(argv)
        
        # Initialize configuration
        config = ConfigManager(args.config if hasattr(args, 'config') else None)
        
        # Setup logging
        log_level = getattr(args, 'log_level', 'INFO')
        console_output = not getattr(args, 'quiet', False)
        logger = setup_logger(
            log_level=log_level,
            console_output=console_output
        )
        
        logger.info("CryptoKit (CK) starting up")
        
        # Handle commands
        command = getattr(args, 'command', None)
        
        if not command or command in ['interactive', 'i']:
            # Start interactive mode
            interactive_mode(config, logger)
        elif command == 'config':
            handle_config_command(args, config, logger)
        elif command in ['encrypt', 'enc', 'e']:
            handle_encrypt_command(args, config, logger)
        elif command in ['decrypt', 'dec', 'd']:
            handle_decrypt_command(args, config, logger)
        elif command in ['hash', 'h']:
            handle_hash_command(args, config, logger)
        else:
            # For now, show that other commands are not implemented
            print(f"Command '{command}' is planned for a future phase.")
            print("Currently available: encrypt, decrypt, hash, interactive mode and config management.")
            return 1
        
        logger.info("CryptoKit (CK) shutting down")
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 1
    except CKException as e:
        print(f"Error: {e.message}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def handle_config_command(args, config: ConfigManager, logger) -> None:
    """Handle configuration commands."""
    action = getattr(args, 'config_action', None)
    
    if action == 'show':
        settings = config.get_all_settings()
        import json
        print(json.dumps(settings, indent=2))
    elif action == 'get':
        value = config.get_setting(args.key, "Not found")
        print(f"{args.key}: {value}")
    elif action == 'set':
        config.set_setting(args.key, args.value)
        print(f"Set {args.key} = {args.value}")
        config.save_config()
    else:
        print("Available config actions: show, get, set")


def handle_encrypt_command(args, config: ConfigManager, logger) -> None:
    """Handle encryption command."""
    from pathlib import Path
    from getpass import getpass
    from ck.services.symmetric import SymmetricEncryptionService
    
    try:
        # Initialize service
        service = SymmetricEncryptionService()
        
        # Validate input file
        input_file = Path(args.file)
        if not input_file.exists():
            print(f"Error: File not found: {input_file}")
            return
        
        # Select algorithm
        algorithm = args.algorithm
        if not algorithm:
            available = service.get_available_algorithms()
            print("Available algorithms:")
            for i, algo in enumerate(available, 1):
                print(f"  {i}. {algo}")
            
            while True:
                try:
                    choice = input("Select algorithm (1-3): ").strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(available):
                        algorithm = available[idx]
                        break
                    else:
                        print("Invalid choice. Please select 1-3.")
                except (ValueError, KeyboardInterrupt):
                    print("\nOperation cancelled.")
                    return
        
        # Get password if needed
        password = args.password
        key_file = Path(args.key_file) if args.key_file else None
        
        if not key_file:
            if not password:
                password = getpass("Enter encryption password: ")
                confirm = getpass("Confirm password: ")
                if password != confirm:
                    print("Error: Passwords do not match.")
                    return
        
        # Set output file
        output_file = Path(args.output) if args.output else None
        
        # Perform encryption
        print(f"Encrypting {input_file} with {algorithm}...")
        encrypted_file, key_file_path = service.encrypt_file(
            input_file=input_file,
            algorithm=algorithm,
            password=password,
            key_file=key_file,
            output_file=output_file
        )
        
        print(f"Encryption successful!")
        print(f"  Encrypted file: {encrypted_file}")
        print(f"  Key file: {key_file_path}")
        
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        print(f"Error: {e}")


def handle_decrypt_command(args, config: ConfigManager, logger) -> None:
    """Handle decryption command."""
    from pathlib import Path
    from ck.services.symmetric import SymmetricEncryptionService
    
    try:
        # Initialize service
        service = SymmetricEncryptionService()
        
        # Validate input files
        encrypted_file = Path(args.file)
        if not encrypted_file.exists():
            print(f"Error: Encrypted file not found: {encrypted_file}")
            return
        
        key_file = Path(args.key_file)
        if not key_file.exists():
            print(f"Error: Key file not found: {key_file}")
            return
        
        # Set output file
        output_file = Path(args.output) if args.output else None
        
        # Perform decryption
        print(f"Decrypting {encrypted_file}...")
        decrypted_file = service.decrypt_file(
            encrypted_file=encrypted_file,
            key_file=key_file,
            output_file=output_file
        )
        
        print(f"Decryption successful!")
        print(f"  Decrypted file: {decrypted_file}")
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        print(f"Error: {e}")


def handle_hash_command(args, config: ConfigManager, logger) -> None:
    """Handle hash command."""
    from pathlib import Path
    from ck.services.hashing import HashingService
    
    try:
        # Initialize service
        service = HashingService()
        
        # Validate target path
        target_path = Path(args.target)
        if not target_path.exists():
            print(f"Error: Target not found: {target_path}")
            return
        
        # Determine if target is file or directory
        if target_path.is_file():
            print(f"Hashing file {target_path} with {args.algorithm.upper()}...")
            hash_value, hash_file_path = service.hash_file(
                file_path=target_path,
                algorithm=args.algorithm,
                save_to_file=not args.no_save
            )
            
            print(f"{args.algorithm.upper()}: {hash_value}")
            if not args.no_save:
                print(f"Hash saved to: {hash_file_path}")
                
        elif target_path.is_dir():
            print(f"Hashing directory {target_path} with {args.algorithm.upper()}...")
            hash_value, hash_file_path = service.hash_directory(
                dir_path=target_path,
                algorithm=args.algorithm,
                save_to_file=not args.no_save
            )
            
            print(f"{args.algorithm.upper()}: {hash_value}")
            if not args.no_save:
                print(f"Hash saved to: {hash_file_path}")
        else:
            print(f"Error: Target is neither a file nor a directory: {target_path}")
            return
        
    except Exception as e:
        logger.error(f"Hashing failed: {e}")
        print(f"Error: {e}")


if __name__ == "__main__":
    sys.exit(main())
