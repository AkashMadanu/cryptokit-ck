#!/usr/bin/env python3
"""
CryptoKit (CK) Installation and Deployment Script

This script helps with installation and deployment of CryptoKit.
"""

import sys
import subprocess
import os
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required.")
        print(f"Current version: {sys.version}")
        return False
    return True

def install_requirements():
    """Install required packages."""
    try:
        print("Installing requirements...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True)
        print("Requirements installed successfully.")
        return True
    except subprocess.CalledProcessError:
        print("Error: Failed to install requirements.")
        return False

def install_package():
    """Install CryptoKit package."""
    try:
        print("Installing CryptoKit package...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], 
                      check=True)
        print("CryptoKit installed successfully.")
        return True
    except subprocess.CalledProcessError:
        print("Error: Failed to install CryptoKit package.")
        return False

def test_installation():
    """Test if CryptoKit is installed correctly."""
    try:
        print("Testing installation...")
        result = subprocess.run([sys.executable, "-m", "ck.cli.main", "--version"], 
                               capture_output=True, text=True, check=True)
        print(f"Installation successful: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError:
        print("Error: Installation test failed.")
        return False

def main():
    """Main installation function."""
    print("CryptoKit (CK) Installation Script")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check if we're in the right directory
    if not Path("setup.py").exists():
        print("Error: Please run this script from the CryptoKit root directory.")
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Install package
    if not install_package():
        sys.exit(1)
    
    # Test installation
    if not test_installation():
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("Installation completed successfully!")
    print("\nYou can now use CryptoKit with:")
    print("  ck --help")
    print("  ck interactive")
    print("  python -m ck.cli.main")

if __name__ == "__main__":
    main()
