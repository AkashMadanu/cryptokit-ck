"""
Configuration Management for CryptoKit (CK)

Handles loading, validation, and management of configuration settings.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Union
from ck.core.exceptions import ConfigurationError


class ConfigManager:
    """
    Centralized configuration management system.
    
    Supports YAML configuration files, environment variable overrides,
    and runtime configuration updates.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to configuration file. If None, uses default.
        """
        self._config: Dict[str, Any] = {}
        self._config_file = config_file or self._get_default_config_path()
        self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        # First check for user config in home directory
        home_config = Path.home() / ".ck" / "config.yaml"
        if home_config.exists():
            return str(home_config)
        
        # Fall back to project default config
        project_root = Path(__file__).parent.parent.parent
        default_config = project_root / "config" / "default.yaml"
        return str(default_config)
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f) or {}
            else:
                # Create default configuration if file doesn't exist
                self._create_default_config()
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading config file: {e}")
    
    def _create_default_config(self) -> None:
        """Create a minimal default configuration."""
        self._config = {
            'general': {
                'log_level': 'INFO',
                'log_file': 'ck.log'
            },
            'encryption': {
                'default_algorithm': 'aes-256-gcm'
            },
            'hashing': {
                'default_algorithm': 'sha256'
            }
        }
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration setting using dot notation.
        
        Args:
            key: Setting key in dot notation (e.g., 'encryption.default_algorithm')
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            
            # Check for environment variable override
            env_var = f"CK_{key.upper().replace('.', '_')}"
            env_value = os.getenv(env_var)
            if env_value is not None:
                return self._convert_env_value(env_value)
            
            return value
        except (KeyError, TypeError):
            return default
    
    def set_setting(self, key: str, value: Any) -> None:
        """
        Set a configuration setting using dot notation.
        
        Args:
            key: Setting key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        # Navigate to the parent dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the final value
        config[keys[-1]] = value
    
    def save_config(self, file_path: Optional[str] = None) -> None:
        """
        Save current configuration to file.
        
        Args:
            file_path: Optional file path. If None, uses current config file.
        """
        save_path = file_path or self._config_file
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._config, f, default_flow_style=False, indent=2)
        except Exception as e:
            raise ConfigurationError(f"Error saving config file: {e}")
    
    def validate_config(self) -> bool:
        """
        Validate the current configuration.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        required_sections = ['general', 'encryption', 'hashing']
        
        for section in required_sections:
            if section not in self._config:
                raise ConfigurationError(f"Missing required section: {section}")
        
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        log_level = self.get_setting('general.log_level', 'INFO')
        if log_level.upper() not in valid_log_levels:
            raise ConfigurationError(f"Invalid log level: {log_level}")
        
        return True
    
    def reload_config(self) -> None:
        """Reload configuration from file."""
        self._load_config()
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get a copy of all configuration settings."""
        return self._config.copy()
    
    def _convert_env_value(self, value: str) -> Union[str, int, float, bool]:
        """
        Convert environment variable string to appropriate Python type.
        
        Args:
            value: Environment variable value
            
        Returns:
            Converted value
        """
        # Try boolean
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        if value.lower() in ('false', 'no', '0', 'off'):
            return False
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific external tool.
        
        Args:
            tool_name: Name of the tool (e.g., 'john', 'hashcat')
            
        Returns:
            Tool configuration dictionary
        """
        return self.get_setting(f'cracking.tools.{tool_name}', {})
    
    def get_algorithm_config(self, category: str, algorithm: str) -> Dict[str, Any]:
        """
        Get configuration for a specific algorithm.
        
        Args:
            category: Algorithm category ('encryption', 'hashing')
            algorithm: Algorithm name
            
        Returns:
            Algorithm configuration dictionary
        """
        return self.get_setting(f'{category}.algorithms.{algorithm}', {})
