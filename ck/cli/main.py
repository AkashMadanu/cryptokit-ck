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
        help="Encrypt files or directories",
        aliases=["enc"]
    )
    encrypt_parser.add_argument(
        "target",
        help="File or directory to encrypt"
    )
    encrypt_parser.add_argument(
        "--algorithm", "-a",
        default="aes-256-gcm",
        help="Encryption algorithm (default: aes-256-gcm)"
    )
    encrypt_parser.add_argument(
        "--output", "-o",
        help="Output file/directory path"
    )
    encrypt_parser.add_argument(
        "--password", "-p",
        help="Encryption password (will prompt if not provided)"
    )
    
    # Decryption commands
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt files or directories",
        aliases=["dec"]
    )
    decrypt_parser.add_argument(
        "target",
        help="File or directory to decrypt"
    )
    decrypt_parser.add_argument(
        "--output", "-o",
        help="Output file/directory path"
    )
    decrypt_parser.add_argument(
        "--password", "-p",
        help="Decryption password (will prompt if not provided)"
    )
    
    # Hashing commands
    hash_parser = subparsers.add_parser(
        "hash",
        help="Generate hashes of files or directories"
    )
    hash_parser.add_argument(
        "target",
        help="File or directory to hash"
    )
    hash_parser.add_argument(
        "--algorithm", "-a",
        default="sha256",
        help="Hash algorithm (default: sha256)"
    )
    hash_parser.add_argument(
        "--output", "-o",
        help="Output file for hash results"
    )
    hash_parser.add_argument(
        "--verify",
        help="Hash file to verify against"
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
    stego_parser = subparsers.add_parser(
        "stego",
        help="Steganography operations"
    )
    stego_subparsers = stego_parser.add_subparsers(
        dest="stego_action",
        help="Steganography actions"
    )
    
    hide_parser = stego_subparsers.add_parser("hide", help="Hide data in file")
    hide_parser.add_argument("cover_file", help="Cover file")
    hide_parser.add_argument("secret_file", help="File containing secret data")
    hide_parser.add_argument("output_file", help="Output file")
    hide_parser.add_argument("--password", "-p", help="Password for encryption")
    
    extract_parser = stego_subparsers.add_parser("extract", help="Extract hidden data")
    extract_parser.add_argument("stego_file", help="File containing hidden data")
    extract_parser.add_argument("--output", "-o", help="Output file for extracted data")
    extract_parser.add_argument("--password", "-p", help="Password for decryption")
    
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
                        "stego", "metadata", "config", "help", "quit"
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
                else:
                    console.print(f"[yellow]'{choice}' functionality coming in Phase {get_phase_number(choice)}![/yellow]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Goodbye![/yellow]")
                break
            except Exception as e:
                logger.error(f"Error in interactive mode: {e}")
                console.print(f"[red]Error: {e}[/red]")
                
    except ImportError:
        print("Interactive mode requires the 'rich' library.")
        print("Install with: pip install rich")
        logger.error("Rich library not available for interactive mode")


def show_interactive_help(console) -> None:
    """Show help in interactive mode."""
    table = Table(title="Available Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="green")
    
    commands = [
        ("encrypt", "Encrypt files/directories", "🟡 Phase 1"),
        ("decrypt", "Decrypt files/directories", "🟡 Phase 1"),
        ("hash", "Generate file hashes", "🔴 Phase 2"),
        ("crack", "Crack hash values", "🔴 Phase 3"),
        ("stego", "Steganography operations", "🔴 Phase 4"),
        ("metadata", "File metadata analysis", "🔴 Phase 5"),
        ("config", "Configuration management", "✅ Available"),
        ("help", "Show this help", "✅ Available"),
        ("quit", "Exit the program", "✅ Available"),
    ]
    
    for cmd, desc, status in commands:
        table.add_row(cmd, desc, status)
    
    console.print(table)


def show_config_menu(console, config: ConfigManager) -> None:
    """Show configuration menu."""
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


def get_phase_number(command: str) -> int:
    """Get the phase number for a command."""
    phase_map = {
        "encrypt": 1, "decrypt": 1,
        "hash": 2,
        "crack": 3,
        "stego": 4,
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
        else:
            # For now, show that other commands are not implemented
            print(f"Command '{command}' is planned for a future phase.")
            print("Currently available: interactive mode and config management.")
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


if __name__ == "__main__":
    sys.exit(main())
