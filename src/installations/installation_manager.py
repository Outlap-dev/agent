import logging
import os
from typing import Dict, List, Set, Any, Optional
from .git_installer import GitInstaller
from .docker_installer import DockerInstaller
from .nixpacks_installer import NixpacksInstaller
from .caddy_installer import CaddyInstaller

logger = logging.getLogger(__name__)

class InstallationManager:
    """
    Manages installation of all tools required by the agent.
    Provides methods to check, install, and query installation status.
    """
    
    def __init__(self, config_path: str = '/etc/pulseup-agent/config'):
        self.config_path = config_path
        self.installers = {
            'git': GitInstaller(config_path),
            'docker': DockerInstaller(config_path),
            'nixpacks': NixpacksInstaller(config_path),
            'caddy': CaddyInstaller(config_path)
        }
        
    def get_installer(self, tool_name: str):
        """Get a specific installer by tool name."""
        return self.installers.get(tool_name)
    
    async def install_tool(self, tool_name: str) -> bool:
        """Install a specific tool."""
        installer = self.get_installer(tool_name)
        if not installer:
            logger.error(f"No installer found for tool: {tool_name}")
            return False
            
        return await installer.check_and_install()
    
    async def install_tools(self, tools: List[str] = None) -> Dict[str, bool]:
        """
        Install multiple tools.
        
        Args:
            tools: List of tool names to install. If None, installs all tools.
        
        Returns:
            Dictionary mapping tool names to installation success status.
        """
        if tools is None:
            tools = list(self.installers.keys())
            
        results = {}
        for tool in tools:
            results[tool] = await self.install_tool(tool)
            
        return results
    
    async def get_installation_status(self) -> Dict[str, bool]:
        """Get the current installation status of all tools."""
        status = {}
        for tool_name, installer in self.installers.items():
            status[tool_name] = await installer.check_installed()
            
        return status
    
    def get_pending_installations(self) -> List[str]:
        """
        Get a list of tools that need to be installed based on the config file.
        This is a sync method that doesn't check actual installation status.
        
        Note: Only returns Caddy as pending, since Git, Docker, and Nixpacks 
        are installed automatically.
        """
        pending_tools = []
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    content = f.read()
                    
                # Only check for Caddy since the others are installed automatically
                installed_marker = "CADDY_INSTALLED=true"
                not_installed_marker = "CADDY_INSTALLED=false"
                
                if not_installed_marker in content:
                    pending_tools.append('caddy')
                elif installed_marker not in content:
                    # If no status, assume it needs to be installed
                    pending_tools.append('caddy')
        except Exception as e:
            logger.error(f"Error reading config file for pending installations: {str(e)}")
            # If error, assume Caddy needs installation
            pending_tools = ['caddy']
                
        return pending_tools 