import logging
from typing import Dict, Any
from src.handlers.base_handler import CommandHandler # Use existing base class
from src.services.ssh_key_service import SSHKeyService

logger = logging.getLogger(__name__)

class AddSSHKeyHandler(CommandHandler):
    COMMAND_NAME = "add_ssh_key"

    def __init__(self):
        # Get ssh_key_service from service manager
        service_manager = self.get_service_manager()
        if service_manager:
            self.ssh_key_service = service_manager.ssh_key_service
        else:
            logger.error("No service manager available for AddSSHKeyHandler")
            self.ssh_key_service = None

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handles the 'add_ssh_key' command.

        Args:
            data: The data payload containing 'public_key' and 'key_uid'.

        Returns:
            The result from SSHKeyService.add_key.
        """
        if not self.ssh_key_service:
            return {"success": False, "error": "SSH key service not available"}
            
        public_key = data.get('public_key')
        # key_uid is primarily for server-side tracking or agent logging
        key_uid = data.get('key_uid', 'unknown') 

        if not public_key:
            logger.error("Missing 'public_key' in add_ssh_key command data.")
            return {"success": False, "error": "Missing 'public_key' in request data."}
        
        logger.info(f"Handling {self.COMMAND_NAME} command for key UID: {key_uid}")
        return await self.ssh_key_service.add_key(public_key, key_uid)

    def get_command_name(self) -> str:
        """Returns the command name this handler manages."""
        return self.COMMAND_NAME 