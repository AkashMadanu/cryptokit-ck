"""
Unit tests for core configuration functionality
"""

import unittest
import tempfile
import os
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from ck.core.config import ConfigManager
from ck.core.exceptions import ConfigurationError


class TestConfigManager(unittest.TestCase):
    """Test cases for ConfigManager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, "test_config.yaml")
        
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_default_config_creation(self):
        """Test that default configuration is created."""
        config = ConfigManager(self.config_file)
        self.assertIsInstance(config.get_all_settings(), dict)
        self.assertIn('general', config.get_all_settings())
    
    def test_get_setting(self):
        """Test getting configuration settings."""
        config = ConfigManager(self.config_file)
        log_level = config.get_setting('general.log_level', 'DEBUG')
        self.assertIsInstance(log_level, str)
    
    def test_set_setting(self):
        """Test setting configuration values."""
        config = ConfigManager(self.config_file)
        config.set_setting('test.value', 'test_data')
        self.assertEqual(config.get_setting('test.value'), 'test_data')
    
    def test_validation(self):
        """Test configuration validation."""
        config = ConfigManager(self.config_file)
        # Should not raise exception for valid config
        self.assertTrue(config.validate_config())


if __name__ == "__main__":
    unittest.main()
