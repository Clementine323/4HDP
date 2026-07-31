import os
import yaml
from typing import List, Optional
from threading import Lock

class ShieldConfig:
    """
    Singleton Configuration Manager for FourHDP.
    Loads settings from a YAML file.
    """
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ShieldConfig, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.config_path = os.path.join(os.getcwd(), 'configs', 'default.yaml')
        self._config = {}
        self.reload()
        self._initialized = True
    
    def reload(self, config_path: Optional[str] = None):
        """Reloads configuration from the specified path or default path."""
        if config_path:
            self.config_path = config_path
            
        if not os.path.exists(self.config_path):
            # Fallback defaults if file missing
            self._config = {
                'mode': 'MONITOR',
                'llm_model_name': 'gpt-4o',
                'sensitive_paths': []
            }
            return

        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f) or {}

    @property
    def mode(self) -> str:
        """Operation mode: 'MONITOR' or 'BLOCK'."""
        return self._config.get('mode', 'MONITOR')

    @property
    def llm_model_name(self) -> str:
        """Name of the LLM model to use for auditing."""
        return (
            os.environ.get('FOURHDP_AUDIT_MODEL')
            or os.environ.get('MODEL_NAME')
            or self._config.get('llm_model_name', 'gpt-4o-mini')
        )

    @property
    def sensitive_paths(self) -> List[str]:
        """List of file paths considered sensitive."""
        return self._config.get('sensitive_paths', [])

    @property
    def openai_api_key(self) -> Optional[str]:
        """OpenAI API Key from environment (preferred) or config."""
        return os.environ.get('OPENAI_API_KEY') or self._config.get('openai_api_key')

    @property
    def openai_base_url(self) -> Optional[str]:
        """OpenAI Base URL from environment (preferred) or config."""
        return os.environ.get('OPENAI_BASE_URL') or self._config.get('openai_base_url')
    
    def get(self, key: str, default=None):
        """Get arbitrary config value."""
        return self._config.get(key, default)
