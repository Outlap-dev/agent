import logging
from typing import Dict, Any, Optional

from src.handlers.base_handler import CommandHandler
# Import the main streaming handler to call its cancel method
from src.handlers.stream_container_logs_handler import StreamContainerLogsHandler

logger = logging.getLogger(__name__)

class StopStreamContainerLogsHandler(CommandHandler):
    """Handles requests to stop streaming Docker container logs for a specific service."""

    def __init__(self):
        # We'll get the stream_handler from command_registry when needed
        self._stream_handler = None

    @property
    def stream_handler(self) -> Optional[StreamContainerLogsHandler]:
        """Lazily get the StreamContainerLogsHandler from the command registry"""
        if self._stream_handler is None:
            # Get service_manager from base class
            service_manager = self.get_service_manager()
            if service_manager and service_manager.command_registry:
                try:
                    # Get the handler for stream_container_logs command
                    self._stream_handler = service_manager.command_registry.get_handler("stream_container_logs")
                except ValueError as e:
                    logger.error(f"Failed to get StreamContainerLogsHandler: {e}")
        return self._stream_handler
        
    @stream_handler.setter
    def stream_handler(self, handler: StreamContainerLogsHandler):
        """Allow setting the stream_handler directly (for HandlerRegistry)"""
        if handler and isinstance(handler, StreamContainerLogsHandler):
            self._stream_handler = handler
            logger.debug("StreamContainerLogsHandler set directly")

    def get_command_name(self) -> str:
        return "stop_stream_container_logs"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stops log streaming for a specific service container.

        Args:
            data: Dictionary containing command parameters:
                - service_uid: ID of the service whose log stream should be stopped.
        Returns:
            Dictionary indicating success or failure of stopping the stream.
        """
        service_uid = data.get('service_uid')

        if not service_uid:
            return {'success': False, 'error': 'Missing required parameter: service_uid'}

        logger.info(f"Received request to stop log streaming for service {service_uid}")

        stream_handler = self.stream_handler
        if not stream_handler:
            return {'success': False, 'error': 'Stream handler not available'}

        try:
            await stream_handler.cancel_streaming_for_service(service_uid)
            return {'success': True, 'message': f'Log streaming stopped for service {service_uid}'}
        except Exception as e:
            logger.error(f"Error trying to stop log stream for service {service_uid}: {e}", exc_info=True)
            return {'success': False, 'error': f'Failed to stop stream: {str(e)}'} 