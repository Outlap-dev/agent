import logging
import os
from typing import Dict, Any
from .base_handler import CommandHandler

logger = logging.getLogger(__name__)

class RestartServerHandler(CommandHandler):
    """Handles restarting the server."""

    def get_command_name(self) -> str:
        return "restart_server"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restarts the server.
        
        Returns:
            Dictionary indicating success or failure.
        """
        try:
            logger.info("Attempting to restart the server...")
            
            # Execute reboot command
            os.system("sudo reboot")
            
            # Return success before reboot completes
            return {
                "success": True,
                "message": "Server restart initiated using command: sudo reboot"
            }

        except Exception as e:
            logger.error(f"Error initiating server restart: {e}")
            return {
                "success": False,
                "error": f"Failed to initiate server restart: {str(e)}"
            }