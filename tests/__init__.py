"""
Test suite for CryptoKit (CK)
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

__all__ = ["run_tests"]

def run_tests():
    """Run the complete test suite."""
    import pytest
    return pytest.main([str(Path(__file__).parent)])

if __name__ == "__main__":
    run_tests()
