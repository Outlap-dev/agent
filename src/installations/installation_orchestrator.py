import logging
from typing import List
from src.installations.installation_manager import InstallationManager

logger = logging.getLogger(__name__)

class InstallationOrchestrator:
    def __init__(self, installation_manager: InstallationManager):
        self.installation_manager = installation_manager
        self.installation_order = [
            'git',      # Git needs to be first for cloning
            'docker',   # Docker needs to be before services that depend on it
            'nixpacks', # Nixpacks depends on Docker
            'caddy'     # Caddy depends on Docker
        ]
        
    async def install_tool(self, tool_name: str) -> bool:
        """Install a single tool and handle errors appropriately"""
        installer = self.installation_manager.get_installer(tool_name)
        if not installer:
            logger.warning(f"No installer found for {tool_name}")
            return False
            
        try:
            if await installer.check_installed():
                logger.info(f"{tool_name} is already installed")
                return True
                
            logger.info(f"Installing {tool_name}...")
            success = await installer.install()
            
            if success:
                logger.info(f"Successfully installed {tool_name}")
            else:
                logger.error(f"Failed to install {tool_name}")
                
            return success
            
        except Exception as e:
            logger.error(f"Error installing {tool_name}: {e}")
            logger.exception(e)
            return False
    
    async def install_required_tools(self) -> List[str]:
        """
        Install all required tools in the correct order.
        Returns a list of successfully installed tools.
        """
        installed_tools = []
        
        for tool in self.installation_order:
            # Special handling for docker-dependent tools
            if tool in ['nixpacks', 'caddy']:
                if 'docker' not in installed_tools:
                    logger.warning(f"Skipping {tool} installation as Docker is not available")
                    continue
            
            if await self.install_tool(tool):
                installed_tools.append(tool)
        
        return installed_tools
    
    async def verify_installations(self) -> bool:
        """Verify that all required tools are installed"""
        for tool in self.installation_order:
            installer = self.installation_manager.get_installer(tool)
            if not installer:
                continue
                
            try:
                if not await installer.check_installed():
                    logger.warning(f"{tool} is not installed")
                    return False
            except Exception as e:
                logger.error(f"Error checking {tool} installation: {e}")
                return False
        
        return True 