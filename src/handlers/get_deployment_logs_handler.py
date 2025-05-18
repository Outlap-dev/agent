import logging
import os
import aiofiles
from typing import Dict, Any, Optional
from datetime import datetime

from src.handlers.base_handler import CommandHandler
from src.services.build_service import DeploymentStatus

logger = logging.getLogger(__name__)

class GetDeploymentLogsHandler(CommandHandler):
    """Handles retrieving deployment logs."""

    def __init__(self):
        """Initialize the handler"""
        self.logs_dir = "/var/log/pulseup/deployments"

    def get_command_name(self) -> str:
        return "get_deployment_logs"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetches build logs from files up until deployment completion.

        Args:
            data: Dictionary containing command parameters:
                - deployment_uid: ID of the deployment whose logs are needed
                - tail: Optional number of lines to return from the end
                - since: Optional ISO timestamp to get logs since

        Returns:
            Dictionary containing all logs up until deployment completion
        """
        deployment_uid = data.get('deployment_uid')
        tail = data.get('tail')
        since = data.get('since')

        if not deployment_uid:
            return {'success': False, 'error': 'Missing required parameter: deployment_uid'}

        try:
            build_log_file = os.path.join(self.logs_dir, f"{deployment_uid}_build.log")
            if not os.path.exists(build_log_file):
                return {'success': False, 'error': f'Build logs not found for deployment {deployment_uid}'}

            async with aiofiles.open(build_log_file, mode='r') as f:
                logs = await f.read()
                if since:
                    logs = self._filter_logs_by_timestamp(logs, since)
                
                # Filter logs up until deployment completion
                logs = self._filter_logs_until_completion(logs)
                
                if tail:
                    logs = self._get_last_n_lines(logs, tail)

            return {
                'success': True,
                'logs': logs
            }

        except Exception as e:
            error_msg = f"Error retrieving build logs: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}

    def _filter_logs_until_completion(self, logs: str) -> str:
        """Filter log lines to only include those up until deployment completion."""
        lines = logs.splitlines()
        filtered_lines = []
        
        for line in lines:
            filtered_lines.append(line)
            
            # Check for deployment status updates
            if f"Deployment status updated to {DeploymentStatus.COMPLETED}" in line:
                break
            # Also break if we see a failure status to include the error
            if f"Deployment status updated to {DeploymentStatus.FAILED}" in line:
                break
        
        return '\n'.join(filtered_lines)

    def _filter_logs_by_timestamp(self, logs: str, since: str) -> str:
        """Filter log lines to only include those after the given timestamp."""
        try:
            target_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
            filtered_lines = []
            
            for line in logs.splitlines():
                try:
                    # Parse timestamp from log line (format: 2024-03-19T10:30:45.123456 - INFO - message)
                    parts = line.split(' - ', 2)
                    if len(parts) >= 2:
                        line_timestamp = parts[0]
                        line_dt = datetime.fromisoformat(line_timestamp)
                        
                        if line_dt >= target_dt:
                            filtered_lines.append(line)
                    else:
                        # If we can't parse the timestamp, include the line
                        filtered_lines.append(line)
                except Exception:
                    # If we can't parse the timestamp, include the line
                    filtered_lines.append(line)
            
            return '\n'.join(filtered_lines) if filtered_lines else ""
        except Exception as e:
            logger.error(f"Error filtering logs by timestamp: {e}")
            return logs

    def _get_last_n_lines(self, logs: str, n: int) -> str:
        """Get the last n lines from the logs."""
        lines = logs.splitlines()
        return '\n'.join(lines[-n:]) if lines else "" 