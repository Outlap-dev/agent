import asyncio
import logging
import os
from typing import List, Dict, Any, Optional
from .base_handler import CommandHandler
from src.installations.installation_manager import InstallationManager

logger = logging.getLogger(__name__)

class ToolsInstallHandler(CommandHandler):
    """Handles the installation of various tools needed for deployment."""
    
    def __init__(self):
        # Get config_path from service manager or use default
        service_manager = self.get_service_manager()
        config_path = service_manager.config_path if service_manager else '/etc/pulseup-agent/config'
        
        self.installation_manager = InstallationManager(config_path)
        self._socket_manager = None
        
    def get_command_name(self) -> str:
        return "install_tools"
    
    @property
    def socket_manager(self):
        if self._socket_manager is None:
            # Try to get socket_manager from service_manager
            service_manager = self.get_service_manager()
            if service_manager:
                self._socket_manager = service_manager.socket_manager
        return self._socket_manager
    
    @socket_manager.setter
    def socket_manager(self, socket_manager):
        self._socket_manager = socket_manager
    
    async def handle(self, payload: dict) -> dict:
        """
        Handles the installation of specified tools.
        
        Payload:
        - tools: Optional list of tool names to install. 
          If not provided, attempts to install all available tools.
          Available values: 'docker', 'git', 'nixpacks', 'caddy'
        
        Returns:
        - status: 'success' or 'error'
        - installed: List of successfully installed tools
        - failed: List of tools that failed to install
        - message: Status message
        """
        logger.info(f"Received command: {self.get_command_name()}")
        
        # Get list of tools to install (default to all if not specified)
        requested_tools = payload.get('tools')
        
        if requested_tools is None:
            # If no tools specified, get all available tools from the installation manager
            requested_tools = list(self.installation_manager.installers.keys())
        elif isinstance(requested_tools, str):
            # Handle case where a single tool name is provided as a string
            requested_tools = [requested_tools]
            
        # Validate requested tools
        valid_tools = set(self.installation_manager.installers.keys())
        invalid_tools = [tool for tool in requested_tools if tool not in valid_tools]
        
        if invalid_tools:
            error_msg = f"Invalid tools requested: {', '.join(invalid_tools)}. Valid options are: {', '.join(valid_tools)}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
        
        # Install the requested tools
        results = await self.installation_manager.install_tools(requested_tools)
        
        # Process results
        installed_tools = [tool for tool, success in results.items() if success]
        failed_tools = [tool for tool, success in results.items() if not success]
        
        # Emit websocket notification about pending installations
        if failed_tools:
            await self._notify_pending_installations(failed_tools)
            
        # Format the response
        if not failed_tools:
            message = f"Successfully installed all requested tools: {', '.join(installed_tools)}"
            status = "success"
        elif not installed_tools:
            message = f"Failed to install any requested tools: {', '.join(failed_tools)}"
            status = "error"
        else:
            message = f"Partially successful. Installed: {', '.join(installed_tools)}. Failed: {', '.join(failed_tools)}"
            status = "partial"
            
        logger.info(message)
        return {
            "status": status,
            "message": message,
            "installed": installed_tools,
            "failed": failed_tools
        }
    
    async def _notify_pending_installations(self, pending_tools: List[str]) -> None:
        """Send a websocket notification about pending tool installations."""
        if not self.socket_manager:
            logger.warning("No socket manager available to notify about pending installations")
            return
            
        try:            
            await self.socket_manager.emit(
                'pending_installations',
                {
                    'pending_tools': pending_tools
                }
            )
        except Exception as e:
            logger.error(f"Error sending pending installations notification: {e}") 