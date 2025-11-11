"""Configuration loader utility"""
import yaml
import os
from pathlib import Path


class ConfigLoader:
    """Load and manage configuration from YAML file"""

    def __init__(self, config_path=None):
        """
        Initialize config loader

        Args:
            config_path: Path to config file. If None, uses default location
        """
        if config_path is None:
            # Default to configs/config.yaml relative to project root
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "osint_tool" / "configs" / "config.yaml"

        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML configuration: {e}")

    def get(self, key_path, default=None):
        """
        Get configuration value by key path

        Args:
            key_path: Dot-separated path to config value (e.g., 'modules.dns_enumeration')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def is_module_enabled(self, module_name):
        """Check if a specific module is enabled"""
        return self.get(f'modules.{module_name}', False)

    def is_tool_enabled(self, tool_name):
        """Check if a specific open source tool is enabled"""
        if not self.get('opensource_tools.enabled', False):
            return False
        return self.get(f'opensource_tools.{tool_name}', False)

    def is_api_enabled(self, api_name):
        """Check if a specific external API is enabled"""
        if not self.get('external_apis.enabled', False):
            return False
        return self.get(f'external_apis.{api_name}.enabled', False)

    def get_api_key(self, api_name):
        """Get API key for a specific service"""
        return self.get(f'external_apis.{api_name}.api_key', '')

    def get_target(self):
        """Get target information"""
        return self.get('target', {})

    def get_general_settings(self):
        """Get general settings"""
        return self.get('general', {})

    def reload(self):
        """Reload configuration from file"""
        self.config = self._load_config()

    def __str__(self):
        """String representation"""
        return f"ConfigLoader(config_path={self.config_path})"


if __name__ == "__main__":
    # Test config loader
    config = ConfigLoader()
    print("Configuration loaded successfully")
    print(f"DNS enumeration enabled: {config.is_module_enabled('dns_enumeration')}")
    print(f"Shodan API enabled: {config.is_api_enabled('shodan')}")
