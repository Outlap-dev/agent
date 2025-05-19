import logging
import os
from typing import List, Optional
from .caddy_installer import CaddyInstaller

logger = logging.getLogger(__name__)

class InstallationManager:
    """
    Manages installation of Caddy required by the agent.
    Provides methods to check, install, and query Caddy installation status.
    """
    
    def __init__(self, config_path: str = '/etc/pulseup-agent/config'):
        self.config_path = config_path
        self.installer = CaddyInstaller(config_path)
        
    def get_installer(self) -> CaddyInstaller:
        """Get the Caddy installer."""
        return self.installer
    
    async def install_caddy(self) -> bool:
        """Install Caddy if not already installed."""
        if not await self.installer.check_installed():
            logger.info("Caddy not found, attempting installation...")
            return await self.installer.install()
        logger.info("Caddy is already installed.")
        return True
    
    async def get_installation_status(self) -> bool:
        """Get the current installation status of Caddy."""
        return await self.installer.check_installed()
    
    def get_pending_installations(self) -> List[str]:
        """
        Get a list of tools that need to be installed based on the config file.
        Only returns Caddy if not installed.
        """
        pending_tools = []
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    content = f.read()
                installed_marker = "CADDY_INSTALLED=true"
                not_installed_marker = "CADDY_INSTALLED=false"
                if not_installed_marker in content:
                    pending_tools.append('caddy')
                elif installed_marker not in content:
                    pending_tools.append('caddy')
        except Exception as e:
            logger.error(f"Error reading config file for pending installations: {str(e)}")
            pending_tools = ['caddy']
        return pending_tools 