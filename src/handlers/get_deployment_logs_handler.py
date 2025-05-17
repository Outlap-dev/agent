import logging
import os
import aiofiles
from typing import Dict, Any

from src.handlers.base_handler import CommandHandler

logger = logging.getLogger(__name__)

class GetDeploymentLogsHandler(CommandHandler):
    """Handles retrieving deployment logs."""

    def __init__(self):
        """Initialize the handler"""
        self.deployment_logs_dir = "/var/log/pulseup/deployments"

    def get_command_name(self) -> str:
        return "get_deployment_logs"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetches deployment logs.

        Args:
            data: Dictionary containing command parameters:
                - deployment_uid: ID of the deployment whose logs are needed
                - include_container_logs: Optional boolean to include container logs

        Returns:
            Dictionary containing the deployment logs
        """
        deployment_uid = data.get('deployment_uid')
        include_container_logs = data.get('include_container_logs', True)

        if not deployment_uid:
            return {'success': False, 'error': 'Missing required parameter: deployment_uid'}

        try:
            # Get deployment log file path
            log_file = os.path.join(self.deployment_logs_dir, f"{deployment_uid}.log")
            container_log_file = os.path.join(self.deployment_logs_dir, f"{deployment_uid}_container.log")

            if not os.path.exists(log_file):
                return {'success': False, 'error': f'Deployment log file not found for {deployment_uid}'}

            # Read deployment logs
            async with aiofiles.open(log_file, mode='r') as f:
                deployment_logs = await f.read()

            result = {
                'success': True,
                'deployment_logs': deployment_logs
            }

            # Include container logs if requested and they exist
            if include_container_logs and os.path.exists(container_log_file):
                async with aiofiles.open(container_log_file, mode='r') as f:
                    container_logs = await f.read()
                result['container_logs'] = container_logs

            return result

        except Exception as e:
            error_msg = f"Error retrieving deployment logs: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg} 