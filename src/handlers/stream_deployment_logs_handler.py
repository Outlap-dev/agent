import asyncio
import logging
from typing import Dict, Any, Optional
import os
import aiofiles
from datetime import datetime

from src.handlers.base_handler import CommandHandler
from src.services.service_manager import ServiceManager

logger = logging.getLogger(__name__)

# Event names for sending log data and errors
DEPLOYMENT_LOG_EVENT = 'deployment_log_chunk'
DEPLOYMENT_LOG_ERROR_EVENT = 'deployment_log_error'

class StreamDeploymentLogsHandler(CommandHandler):
    """Handles streaming deployment logs over WebSocket to the server."""

    def __init__(self):
        """Initialize the handler"""
        service_manager = self.get_service_manager()
        self.service_manager = service_manager
        self.socket_manager = service_manager.socket_manager
        self.deployment_logs_dir = "/var/log/pulseup/deployments"

        # Store active streaming tasks: {deployment_uid: asyncio.Task}
        self._streaming_tasks: Dict[str, asyncio.Task] = {}

    def get_command_name(self) -> str:
        return "stream_deployment_logs"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initiates log streaming for a deployment to the server.

        Args:
            data: Dictionary containing command parameters:
                - deployment_uid: ID of the deployment whose logs are needed
                - from_timestamp: Optional ISO timestamp to fetch logs from
        Returns:
            Dictionary indicating success or failure of initiating the stream
        """
        if not self.service_manager:
            return {'success': False, 'error': 'Service manager not available'}

        deployment_uid = data.get('deployment_uid')
        from_timestamp = data.get('from_timestamp')

        if not deployment_uid:
            return {'success': False, 'error': 'Missing required parameter: deployment_uid'}

        # If there's an existing stream, cancel it before starting a new one
        if deployment_uid in self._streaming_tasks and not self._streaming_tasks[deployment_uid].done():
            logger.info(f"Cancelling existing log stream for deployment {deployment_uid}")
            await self.cancel_streaming_for_deployment(deployment_uid)
            await asyncio.sleep(0.1)

        logger.info(f"Initiating log stream for deployment {deployment_uid}")

        # Create and start the background task for streaming
        streaming_task = asyncio.create_task(
            self._stream_logs(deployment_uid, from_timestamp),
            name=f"deployment_log_stream_{deployment_uid}"
        )
        self._streaming_tasks[deployment_uid] = streaming_task

        # Add callback to remove task from dict when done
        streaming_task.add_done_callback(
            lambda t, duid=deployment_uid: self._task_done_callback(duid, t)
        )

        return {'success': True, 'message': f'Log streaming started for deployment {deployment_uid}'}

    def _task_done_callback(self, deployment_uid: str, task: asyncio.Task):
        """Callback executed when a streaming task finishes or is cancelled."""
        task_name = task.get_name()
        logger.debug(f"Callback executing for task '{task_name}' (deployment: {deployment_uid})")
        self._streaming_tasks.pop(deployment_uid, None)

        is_cancelled = task.cancelled()
        final_exception = None if is_cancelled else task.exception()

        if final_exception:
            if isinstance(final_exception, asyncio.CancelledError):
                logger.warning(f"Log streaming task '{task_name}' cancelled")
            else:
                logger.error(f"Log streaming task '{task_name}' ended with error: {final_exception}")
        else:
            logger.info(f"Log streaming task '{task_name}' finished normally")

    async def _stream_logs(self, deployment_uid: str, from_timestamp: Optional[str] = None):
        """Stream logs for a specific deployment."""
        log_file = os.path.join(self.deployment_logs_dir, f"{deployment_uid}.log")
        container_log_file = os.path.join(self.deployment_logs_dir, f"{deployment_uid}_container.log")

        if not os.path.exists(log_file):
            error_msg = f"Deployment log file not found for {deployment_uid}"
            logger.error(error_msg)
            await self._send_error(deployment_uid, error_msg)
            return

        try:
            # First send existing logs
            async with aiofiles.open(log_file, mode='r') as f:
                content = await f.read()
                if content:
                    # Filter by timestamp if needed
                    if from_timestamp:
                        filtered_content = self._filter_logs_by_timestamp(content, from_timestamp)
                        content = filtered_content or "No logs found after the specified timestamp.\n"

                    await self.socket_manager.emit(
                        DEPLOYMENT_LOG_EVENT,
                        {'deployment_uid': deployment_uid, 'log': content, 'existing': True}
                    )

            # If container log file exists, send those too
            if os.path.exists(container_log_file):
                async with aiofiles.open(container_log_file, mode='r') as f:
                    content = await f.read()
                    if content:
                        await self.socket_manager.emit(
                            DEPLOYMENT_LOG_EVENT,
                            {
                                'deployment_uid': deployment_uid,
                                'log': content,
                                'existing': True,
                                'container_logs': True
                            }
                        )

            # Now watch for new content
            async for line in self._tail_file(log_file):
                await self.socket_manager.emit(
                    DEPLOYMENT_LOG_EVENT,
                    {'deployment_uid': deployment_uid, 'log': line, 'existing': False}
                )

        except asyncio.CancelledError:
            logger.info(f"Log streaming cancelled for deployment {deployment_uid}")
            raise
        except Exception as e:
            error_msg = f"Error streaming deployment logs: {str(e)}"
            logger.error(error_msg)
            await self._send_error(deployment_uid, error_msg)

    async def _tail_file(self, filename: str):
        """Generator that yields new lines in a file as they are written."""
        async with aiofiles.open(filename, mode='r') as f:
            # Seek to end
            await f.seek(0, 2)
            while True:
                line = await f.readline()
                if not line:
                    try:
                        await asyncio.sleep(0.1)  # Wait briefly before next attempt
                    except asyncio.CancelledError:
                        break
                else:
                    yield line.strip()

    def _filter_logs_by_timestamp(self, content: str, from_timestamp: str) -> Optional[str]:
        """Filter log lines to only include those after the given timestamp."""
        try:
            target_dt = datetime.fromisoformat(from_timestamp.replace('Z', '+00:00'))
            filtered_lines = []
            
            for line in content.splitlines():
                try:
                    # Parse timestamp from log line (format: 2024-03-19T10:30:45.123456 - INFO - message)
                    line_timestamp = line.split(' - ')[0]
                    line_dt = datetime.fromisoformat(line_timestamp)
                    
                    if line_dt >= target_dt:
                        filtered_lines.append(line)
                except Exception:
                    # If we can't parse the timestamp, include the line
                    filtered_lines.append(line)
            
            return '\n'.join(filtered_lines) if filtered_lines else None
        except Exception as e:
            logger.error(f"Error filtering logs by timestamp: {e}")
            return content

    async def _send_error(self, deployment_uid: str, error_message: str):
        """Sends an error message back to the server."""
        try:
            await self.socket_manager.emit(
                DEPLOYMENT_LOG_ERROR_EVENT,
                {'deployment_uid': deployment_uid, 'error': error_message}
            )
        except Exception as e:
            logger.error(f"Failed to send error message for {deployment_uid}: {e}")

    async def cancel_streaming_for_deployment(self, deployment_uid: str):
        """Cancels the streaming task for a given deployment ID."""
        if deployment_uid in self._streaming_tasks:
            task = self._streaming_tasks[deployment_uid]
            if not task.done():
                logger.info(f"Cancelling log streaming for deployment {deployment_uid}")
                task.cancel()
            else:
                self._streaming_tasks.pop(deployment_uid, None)
                logger.debug(f"Log streaming task for deployment {deployment_uid} was already done") 