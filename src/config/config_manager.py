from typing import Optional
import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class ConfigManager:
    _instance: Optional['ConfigManager'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.system_config = '/etc/pulseup-agent/config'
        self.local_config = '.env'
        self.config_loaded = False
        self._config = {}
        
    def load_configuration(self) -> bool:
        """
        Load configuration from both system and local config files.
        Local config takes precedence for initial loading.
        """
        # First try to load from .env file (for initial setup and local development)
        if os.path.exists(self.local_config):
            load_dotenv(self.local_config)
            self.config_loaded = True
        
        # Then load from system config (will override .env if variables exist in both)
        if os.path.exists(self.system_config):
            load_dotenv(self.system_config)
            self.config_loaded = True
            
        if not self.config_loaded:
            logger.error("No configuration file found. Please create either /etc/pulseup-agent/config or .env")
            return False
            
        # Cache all environment variables
        self._cache_config()
        return True
    
    def _cache_config(self):
        """Cache all relevant environment variables"""
        required_vars = [
            'WEBSOCKET_URL',
            'AGENT_TOKEN'
        ]
        
        for var in required_vars:
            self._config[var] = os.getenv(var)
    
    @property
    def websocket_url(self) -> str:
        """Get the WebSocket URL with fallback"""
        return self._config.get('WEBSOCKET_URL') or 'ws://ws.pulseup.io/ws/agent'
    
    @property
    def agent_token(self) -> Optional[str]:
        """Get the agent token"""
        return self._config.get('AGENT_TOKEN')
    
    @property
    def config_path(self) -> str:
        """Get the system config path"""
        return self.system_config
    
    def validate_config(self) -> bool:
        """Validate that all required configuration is present"""
        return all([self.websocket_url, self.agent_token]) 