from .base_handler import CommandHandler
from typing import Dict, Any
import psutil  # Example: Using psutil to get stats
from src.services.docker_service import DockerService

class GetServiceLogsHandler(CommandHandler):
    """Handles the 'get_service_logs' command"""
    
    def __init__(self):
        self.docker_service = DockerService()

    def get_command_name(self) -> str:
        return "get_service_logs"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetches live system statistics.

        Args:
            data: Dictionary containing command parameters (currently unused)

        Returns:
            Dictionary containing live system stats (CPU, memory, disk)
        """
        service_uid = data.get('service_uid')
        if not service_uid:
            return {'success': False, 'error': 'Missing required parameter: service_uid'}

        container = await self.docker_service.get_container_by_service_uid(service_uid)
        if not container:
            return {'success': False, 'error': 'Container not found'}

        # container.logs() with stream=False returns bytes directly, not awaitable
        logs_bytes = container.logs(tail=100, timestamps=True) 
        return {'success': True, 'logs': logs_bytes.decode('utf-8', errors='replace')}
