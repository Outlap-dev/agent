import logging
import os
from typing import Dict, Any
from src.handlers.base_handler import CommandHandler

logger = logging.getLogger(__name__)

# Uninstall flag file path
UNINSTALL_FLAG_FILE = "/var/run/pulseup-agent/delete-needed"

class UninstallAgentHandler(CommandHandler):
    """Handles agent uninstallation requests."""

    def get_command_name(self) -> str:
        return "uninstall_agent"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle the agent uninstallation request by creating a flag file.
        
        Args:
            data: Dictionary containing any additional data (not used)
                
        Returns:
            Dictionary containing the uninstallation request result
        """
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(UNINSTALL_FLAG_FILE), exist_ok=True)
            
            # Create the uninstall flag file
            with open(UNINSTALL_FLAG_FILE, 'w') as f:
                f.write('')  # Empty file is sufficient as a flag
            
            logger.info("Agent uninstallation requested via flag file")
            return {'success': True}
            
        except Exception as e:
            error_msg = f"Error requesting agent uninstallation: {e}"
            logger.error(error_msg, exc_info=True)
            return {'success': False, 'error': error_msg}