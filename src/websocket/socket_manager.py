import socketio
import logging
from typing import Dict, Any, Optional

from src.services.service_registry import ServiceRegistry
from src.websocket.event_handler import WebSocketEventHandler
from src.services.status_service import StatusService

logger = logging.getLogger(__name__)

class SocketManager:
    """Manages WebSocket connections and communication with the server."""
    
    def __init__(self, base_url: str, token: str):
        """Initialize the socket manager."""
        self.base_url = base_url
        self.token = token
        self.namespace = '/ws/agent'
        
        # Initialize Socket.IO client with logging disabled
        self.sio = socketio.AsyncClient(logger=False, engineio_logger=False)
        
        # Get service registry
        self.services = ServiceRegistry()
        
        # Initialize supporting services
        self.status_service = StatusService(self.sio, self.namespace)
        self.services.register(StatusService, self.status_service)
        
        # Initialize event handler
        self.event_handler = WebSocketEventHandler(self.sio, self.namespace)
        
    @property
    def connected(self) -> bool:
        """Check if socket is connected."""
        return self.sio.connected
    
    async def connect(self):
        """Establish connection to the WebSocket server."""
        try:
            # Register event handlers before connecting
            self.event_handler.register_handlers()
            
            logger.info("Connecting to PulseUp...")
            await self.sio.connect(
                self.base_url,
                transports=['websocket'],
                socketio_path='socket.io',
                namespaces=[self.namespace],
                headers={"Authorization": f"Bearer {self.token}"},
            )
            await self.sio.wait()
            
        except socketio.exceptions.ConnectionError as e:
            logger.error(f"Failed to connect to server: {e}")
            await self.disconnect()
            raise
            
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
            await self.disconnect()
            raise
    
    async def disconnect(self):
        """Disconnect from the WebSocket server."""
        try:
            if self.connected:
                await self.sio.disconnect()
                logger.info("Disconnected from server.")
        except Exception as e:
            logger.error(f"Error during disconnect: {e}")
        finally:
            if hasattr(self.sio, 'http') and self.sio.http:
                await self.sio.http.close()
    
    async def emit(self, event: str, data: Any):
        """Emit an event to the server."""
        if not self.connected:
            logger.warning(f"Cannot emit event '{event}': Socket not connected")
            return
            
        try:
            await self.sio.emit(event, data, namespace=self.namespace)
        except Exception as e:
            logger.error(f"Failed to emit event '{event}': {e}")
            raise
    
    async def get_service_env_vars(self, service_uid: str) -> Dict[str, Any]:
        """Get environment variables for a service."""
        return await self.status_service.get_service_env_vars(service_uid)
    
    async def update_service_status(self, service_uid: str, status: str, error_message: Optional[str] = None):
        """Update service status."""
        await self.status_service.update_service_status(service_uid, status, error_message)
    
    async def update_deployment_status(self, deployment_uid: str, status: str, error_message: Optional[str] = None):
        """Update deployment status."""
        await self.status_service.update_deployment_status(deployment_uid, status, error_message)