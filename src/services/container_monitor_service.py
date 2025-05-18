import logging
import asyncio
from typing import Dict, Optional
from src.services.docker_service import DockerService
from src.services.service_status import ServiceStatus
from src.websocket.socket_manager import SocketManager

logger = logging.getLogger(__name__)

class ContainerMonitorService:
    """Service for monitoring container status changes"""
    
    def __init__(self, docker_service: DockerService = None, socket_manager: SocketManager = None):
        """
        Initialize the container monitor service.
        
        Args:
            docker_service: Docker service instance
            socket_manager: Socket manager instance for sending status updates
        """
        self.docker_service = docker_service
        self.socket_manager = socket_manager
        self._last_status: Dict[str, str] = {}  # Store last known status for each container
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
    
    def set_socket_manager(self, socket_manager: SocketManager):
        """Set the socket manager instance"""
        self.socket_manager = socket_manager
    
    def set_docker_service(self, docker_service: DockerService):
        """Set the docker service instance"""
        self.docker_service = docker_service
    
    async def _get_container_status(self, container_name: str) -> Optional[str]:
        """
        Get the current status of a container
        
        Args:
            container_name: Name of the container to check
            
        Returns:
            Current status string or None if container not found
        """
        try:
            if not self.docker_service:
                logger.error("Docker service not available")
                return None
                
            # Check if container exists
            exists = await self.docker_service.container_exists(container_name)
            if not exists:
                return None
                
            # Get container object
            container = self.docker_service.client.containers.get(container_name)
            return container.status
            
        except Exception as e:
            logger.error(f"Error getting container status for {container_name}: {e}")
            return None
    
    async def _check_container_status(self, service_uid: str):
        """
        Check status of both app and db containers for a service
        
        Args:
            service_uid: Service UID to check
        """
        # Check app container (both blue and green)
        app_container_blue = f"pulseup-app-{service_uid}-blue"
        app_container_green = f"pulseup-app-{service_uid}-green"
        db_container = f"pulseup-db-{service_uid}"
        
        # Get current status for each container
        blue_status = await self._get_container_status(app_container_blue)
        green_status = await self._get_container_status(app_container_green)
        db_status = await self._get_container_status(db_container)
        
        # Convert Docker status to service status
        if blue_status:
            current_status = ServiceStatus.from_docker_status(blue_status)
            last_status = self._last_status.get(app_container_blue)
            if current_status != last_status:
                await self._emit_status_update(service_uid, current_status)
                self._last_status[app_container_blue] = current_status
        
        if green_status:
            current_status = ServiceStatus.from_docker_status(green_status)
            last_status = self._last_status.get(app_container_green)
            if current_status != last_status:
                await self._emit_status_update(service_uid, current_status)
                self._last_status[app_container_green] = current_status
        
        if db_status:
            current_status = ServiceStatus.from_docker_status(db_status)
            last_status = self._last_status.get(db_container)
            if current_status != last_status:
                await self._emit_status_update(service_uid, current_status)
                self._last_status[db_container] = current_status
    
    async def _emit_status_update(self, service_uid: str, status: str):
        """
        Emit a status update for a service
        
        Args:
            service_uid: Service UID that changed status
            status: New status
        """
        if self.socket_manager:
            await self.socket_manager.update_service_status(service_uid, status)
        else:
            logger.warning(f"Socket manager not available to send status update for {service_uid}")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Get list of all containers with our prefixes
                containers = self.docker_service.client.containers.list(all=True)
                service_uids = set()
                
                for container in containers:
                    name = container.name
                    if name.startswith('pulseup-app-') or name.startswith('pulseup-db-'):
                        # Extract service_uid from container name
                        parts = name.split('pulseup-app-')
                        if len(parts) >= 2:
                            service_uid = parts[1]
                            if name.endswith('-blue') or name.endswith('-green'):
                                service_uid = service_uid[:-5]  # Remove -blue or -green
                            service_uids.add(service_uid)
                
                # Check status for each service
                for service_uid in service_uids:
                    await self._check_container_status(service_uid)
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in container monitor loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def start(self):
        """Start the container monitor"""
        if self._running:
            return
            
        if not self.docker_service:
            logger.error("Cannot start container monitor: Docker service not available")
            return
            
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
    
    async def stop(self):
        """Stop the container monitor"""
        if not self._running:
            return
            
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None
